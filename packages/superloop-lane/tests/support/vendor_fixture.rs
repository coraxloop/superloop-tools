//! Vendor image fixtures enter through the production lane executable.

use serde_json::{Value, json};
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub fn file(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode");
}

// A static x86-64 fixture emits version at argc=2 and help at argc=3. It has
// no interpreter, libraries, shell or host installation dependency.
fn codex_program() -> Vec<u8> {
    let mut bytes = vec![0_u8; 120];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x0040_0078_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    bytes[88..96].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
    bytes.extend_from_slice(&[0x48, 0x83, 0x3c, 0x24, 3, 0x75, 33]);
    let help = b"  --json\n  --sandbox\n  --add-dir\n  --skip-git-repo-check\n  -C, --cd\n  -o, --output-last-message\n";
    let mut patches = Vec::new();
    for text in [help.as_slice(), b"codex-cli 0.1.0\n".as_slice()] {
        bytes.extend_from_slice(&[0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x48, 0x8d, 0x35]);
        let offset = bytes.len();
        bytes.extend_from_slice(&[0; 4]);
        bytes.push(0xba);
        bytes.extend_from_slice(
            &u32::try_from(text.len())
                .expect("fixture size")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&[0x0f, 0x05, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]);
        patches.push((offset, text));
    }
    for (offset, text) in patches {
        let displacement = i32::try_from(bytes.len() - offset - 4).expect("fixture displacement");
        bytes[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
        bytes.extend_from_slice(text);
    }
    let size = u64::try_from(bytes.len()).expect("fixture size");
    bytes[96..104].copy_from_slice(&size.to_le_bytes());
    bytes[104..112].copy_from_slice(&size.to_le_bytes());
    bytes
}

pub struct Fixture {
    pub root: tempfile::TempDir,
    pub codex: bool,
    pub claude: bool,
    pub claude_hash: String,
    pub template: PathBuf,
}

impl Fixture {
    pub fn new(codex: bool, claude: bool) -> Self {
        let root = tempfile::TempDir::new_in("/tmp").expect("small protected program fixture");
        let home = root.path();
        for relative in [
            "",
            ".config",
            ".config/loops",
            ".config/loops/alpha",
            ".cache",
            ".cache/tmp",
        ] {
            let path = home.join(relative);
            fs::create_dir_all(&path).expect("fixture directories");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("directory mode");
        }
        file(&home.join(".config/loops/registry.toml"), b"namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{name = 'alpha', uid = 41001, launch = 'src'}]\n", 0o600);
        let vendors: Vec<_> = [(codex, "codex = []"), (claude, "claude = []")]
            .into_iter()
            .filter_map(|(present, row)| present.then_some(row))
            .collect();
        file(
            &home.join(".config/loops/alpha/workers.toml"),
            format!("vendor_hosts = {{ {} }}\n", vendors.join(", ")).as_bytes(),
            0o600,
        );
        file(&home.join("codex"), &codex_program(), 0o700);
        file(&home.join("codex-code-mode-host"), &codex_program(), 0o700);
        file(
            &home.join("claude"),
            &fs::read("/usr/bin/true").expect("native fixture program"),
            0o700,
        );
        let claude_hash = superloop_lane::build::sha256(&home.join("claude")).expect("Claude hash");
        let mut help = String::new();
        for option in superloop_lane::build::payload::CLAUDE_EXEC_OPTIONS {
            writeln!(help, "  {option}").expect("fixture help");
        }
        help.push_str("stream-json bypassPermissions acceptEdits plan\n");
        let probe = json!({"sha256":claude_hash,"version":"0.1.0 (Claude Code)\n","help":help,"interpreter":{"path":"/lib64/ld-linux-x86-64.so.2","sha256":"c".repeat(64)},"libraries":[{"path":"/lib64/libc.so.6","sha256":"d".repeat(64)}]});
        file(
            &home.join("probe.json"),
            &serde_json::to_vec(&probe).expect("fixture probe"),
            0o600,
        );
        file(
            &home.join("podman"),
            br"#!/usr/bin/python3
import json, os, sys
root = os.path.dirname(__file__)
args = sys.argv[1:]
with open(root + '/calls', 'a') as log:
    log.write(json.dumps(args) + '\n')
if args[:2] == ['image', 'exists']:
    sys.exit(0)
if args[:2] == ['image', 'inspect']:
    print('b' * 64)
elif args[0] == 'build':
    assert '--network=none' in args and '--pull=never' in args
elif args[0] == 'run' and '--entrypoint=/usr/bin/python3' in args:
    assert '--network=none' in args and '--read-only' in args
    assert not any('mount' in word for word in args)
    print(open(root + '/probe.json').read())
elif args[0] == 'run':
    print('glibc 1\nsocat 1')
else:
    sys.exit(71)
",
            0o700,
        );
        Self {
            root,
            codex,
            claude,
            claude_hash,
            template: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data"),
        }
    }

    pub fn call(&self) -> Output {
        self.call_with(&[])
    }

    pub fn call_with(&self, extra: &[&str]) -> Output {
        let home = self.root.path();
        let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
        command
            .env("HOME", home)
            .env_remove("ENTER_LOOP_REGISTRY")
            .args([
                "build",
                "alpha",
                "--base-image",
                &format!("registry.example/base@sha256:{}", "a".repeat(64)),
                "--podman-bin",
            ])
            .arg(home.join("podman"))
            .arg("--template-dir")
            .arg(&self.template);
        if self.codex {
            command
                .arg("--codex-bin")
                .arg(home.join("codex"))
                .arg("--codex-host-bin")
                .arg(home.join("codex-code-mode-host"))
                .args([
                    "--codex-version",
                    "0.1.0",
                    "--codex-sha256",
                    &superloop_lane::build::sha256(&home.join("codex")).expect("hash"),
                    "--codex-host-sha256",
                    &superloop_lane::build::sha256(&home.join("codex-code-mode-host"))
                        .expect("hash"),
                    "--codex-source",
                    "https://fixture.example/codex",
                ]);
        }
        if self.claude {
            command.arg("--claude-bin").arg(home.join("claude")).args([
                "--claude-version",
                "0.1.0",
                "--claude-sha256",
                &self.claude_hash,
                "--claude-source",
                "https://fixture.example/claude",
            ]);
        }
        command
            .args(extra)
            .output()
            .expect("production build command")
    }

    pub fn mutate_probe(&self, change: impl FnOnce(&mut Value)) {
        let path = self.root.path().join("probe.json");
        let mut value: Value =
            serde_json::from_slice(&fs::read(&path).expect("probe")).expect("JSON");
        change(&mut value);
        file(
            &path,
            &serde_json::to_vec(&value).expect("probe JSON"),
            0o600,
        );
    }
}

pub fn successful(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("build report")
}
