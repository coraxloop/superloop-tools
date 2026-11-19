//! Exercise the entered access-only receiver without a vendor or live sign-in.

use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn projection(refresh: &str) -> Vec<u8> {
    json!({"auth_mode":"chatgptAuthTokens","OPENAI_API_KEY":null,
        "tokens":{"id_token":"fictional-id","access_token":"fictional-access",
            "refresh_token":refresh,"account_id":"fictional-account"},
        "last_refresh":"2026-10-05T00:00:00Z"})
    .to_string()
    .into_bytes()
}

fn receiver(home: &Path, entered_home: &Path, uid: u32, input: &[u8]) -> Output {
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", "-c", include_str!("../src/door_sign_in_private.py")])
        .arg(uid.to_string())
        .arg(home)
        .arg("5000")
        .env("HOME", entered_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("receiver child");
    child
        .stdin
        .take()
        .expect("receiver pipe")
        .write_all(input)
        .expect("fictional projection");
    child.wait_with_output().expect("receiver report")
}

fn private(root: &Path) -> std::path::PathBuf {
    let home = root.join("loop/private");
    fs::create_dir_all(&home).expect("private home");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("private mode");
    home
}

/// ´test:integration:door-projection-replaces-renewable-leftover-and-stale-temporary´
#[test]
fn door_projection_replaces_renewable_leftover_and_stale_temporary() {
    let root = tempfile::tempdir().expect("fixture root");
    let home = private(root.path());
    let config = home.join(".codex");
    fs::create_dir(&config).expect("configuration");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("config mode");
    let destination = config.join("auth.json");
    fs::write(&destination, b"fictional renewable leftover").expect("leftover");
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).expect("leftover mode");
    let stale = config.join(".door-auth-00000000000000000000000000000001");
    fs::write(&stale, b"fictional stale temporary").expect("stale temporary");
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).expect("stale mode");
    let input = projection("");
    let output = receiver(&home, &home, nix::unistd::Uid::effective().as_raw(), &input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("receipt");
    assert_eq!(report["published"], true);
    assert!(report.get("sha256").is_none());
    assert!(!stale.exists());
    assert_eq!(fs::read(destination).expect("new projection"), input);
    assert!(
        !output
            .stdout
            .windows(b"fictional-access".len())
            .any(|part| part == b"fictional-access")
    );
}

/// ´test:integration:door-projection-custody-and-evidence-exclude-secrets´
#[test]
fn door_projection_custody_and_evidence_exclude_secrets() {
    let root = tempfile::tempdir().expect("fixture root");
    let home = private(root.path());
    let uid = nix::unistd::Uid::effective().as_raw();
    let access = projection("");
    for (name, entered, selected, input) in [
        ("wrong-uid", home.as_path(), uid + 1, access.clone()),
        ("wrong-home", root.path(), uid, access.clone()),
        (
            "renewable",
            home.as_path(),
            uid,
            projection("fictional-renewer"),
        ),
        ("malformed", home.as_path(), uid, b"{".to_vec()),
        ("oversized", home.as_path(), uid, vec![b'x'; 65_537]),
    ] {
        let output = receiver(&home, entered, selected, &input);
        assert!(!output.status.success(), "{name}");
        assert!(!home.join(".codex/auth.json").exists(), "{name}");
        assert!(
            !output
                .stdout
                .windows(b"fictional-renewer".len())
                .any(|part| part == b"fictional-renewer")
        );
        assert!(
            !output
                .stderr
                .windows(b"fictional-renewer".len())
                .any(|part| part == b"fictional-renewer")
        );
    }
    let config = home.join(".codex");
    if !config.exists() {
        fs::create_dir(&config).expect("config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("config mode");
    }
    std::os::unix::fs::symlink(root.path().join("outside"), config.join("auth.json"))
        .expect("unsafe destination");
    let refused = receiver(&home, &home, uid, &access);
    assert!(!refused.status.success());
    assert!(config.join("auth.json").is_symlink());
    fs::remove_file(config.join("auth.json")).expect("remove unsafe fixture");
    let allowed = receiver(&home, &home, uid, &access);
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        !allowed
            .stdout
            .windows(b"fictional-access".len())
            .any(|part| part == b"fictional-access")
    );

    mapped_identity_case();
}

fn mapped_identity_case() {
    // The owner, entered loop and worker are three mapped identities in the
    // same rootless namespace. The loop alone may receive this projection.
    let mapped = tempfile::Builder::new()
        .prefix("door-projection-identities-")
        .tempdir_in("/var/tmp")
        .expect("mapped fixture root");
    fs::set_permissions(mapped.path(), fs::Permissions::from_mode(0o711))
        .expect("searchable mapped root");
    let script = r"
import json, os, pathlib, shutil, subprocess, sys
root=pathlib.Path(sys.argv[1]); receiver=sys.argv[2]
home=root/'loop'/'private'
home.mkdir(parents=True)
os.chmod(home.parent,0o711)
os.chown(home,1,1); os.chmod(home,0o700)
payload=json.dumps({'auth_mode':'chatgptAuthTokens','OPENAI_API_KEY':None,
 'tokens':{'id_token':'fictional-id','access_token':'fictional-access',
           'refresh_token':'','account_id':'fictional-account'},
 'last_refresh':'2026-10-05T00:00:00Z'}).encode()
def run(uid):
 def enter():
  os.setgroups([]); os.setgid(uid); os.setuid(uid)
 return subprocess.run(['/usr/bin/python3','-I','-c',receiver,str(uid),str(home),'5000'],
                       env=dict(os.environ,HOME=str(home)),input=payload,
                       capture_output=True,preexec_fn=enter,timeout=20)
try:
 worker=run(2)
 assert worker.returncode==2,worker.stderr.decode()
 assert not (home/'.codex/auth.json').exists()
 loop=run(1)
 assert loop.returncode==0,loop.stderr.decode()
 assert (home/'.codex/auth.json').read_bytes()==payload
 for stream in (loop.stdout,loop.stderr,worker.stdout,worker.stderr):
  assert b'fictional-access' not in stream and b'fictional-renewer' not in stream
 assert 'sha256' not in json.loads(loop.stdout)
finally:
 shutil.rmtree(root/'loop')
";
    let identities = Command::new("/usr/bin/podman")
        .args(["unshare", "/usr/bin/python3", "-I", "-c", script])
        .arg(mapped.path())
        .arg(include_str!("../src/door_sign_in_private.py"))
        .output()
        .expect("mapped identities fixture");
    assert!(
        identities.status.success(),
        "{}",
        String::from_utf8_lossy(&identities.stderr)
    );
}

/// ´test:integration:door-sign-in-receiver-admits-only-private-home-traversal-acl´
#[test]
fn door_sign_in_receiver_admits_only_private_home_traversal_acl() {
    let root = tempfile::tempdir().expect("fixture root");
    let script = r"
import json, os, pathlib, struct, subprocess, sys
root = pathlib.Path(sys.argv[1])
receiver = sys.argv[2]
undefined = 2**32 - 1
service = os.geteuid() + 1
base = [(1, 7, undefined), (2, 1, service), (4, 0, undefined),
        (16, 1, undefined), (32, 0, undefined)]
def acl(entries):
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in entries)
cases = [('plain', None, 0o700, None, True),
         ('mail', base, 0o710, None, True),
         ('plain-group', None, 0o710, None, False),
         ('wide-mask', base[:3] + [(16, 5, undefined)] + base[4:], 0o750, None, False),
         ('read-entry', [base[0], (2, 4, service), base[2], (16, 4, undefined), base[4]], 0o740, None, False),
         ('write-entry', [base[0], (2, 3, service), base[2], (16, 3, undefined), base[4]], 0o730, None, False),
         ('second-entry', base[:2] + [(2, 1, service + 1)] + base[2:], 0o710, None, False),
         ('default', base, 0o710, base, False),
         ('plain-default', None, 0o700, base, False),
         ('group-entry', base[:2] + [(4, 1, undefined)] + base[3:], 0o710, None, False),
         ('special-mode', base, 0o1710, None, False),
         ('other-access', base[:-1] + [(32, 1, undefined)], 0o711, None, False)]
payload = json.dumps({'auth_mode':'chatgptAuthTokens','OPENAI_API_KEY':None,
    'tokens':{'id_token':'fictional-id','access_token':'fictional-access',
              'refresh_token':'','account_id':'fictional-account'},
    'last_refresh':'2026-10-05T00:00:00Z'}).encode()
for name, entries, mode, default, allowed in cases:
    home = root / name / 'private'
    home.mkdir(parents=True, mode=0o700)
    if entries is not None:
        os.setxattr(home, 'system.posix_acl_access', acl(entries))
    if default is not None:
        os.setxattr(home, 'system.posix_acl_default', acl(default))
    os.chmod(home, mode)
    result = subprocess.run([sys.executable, '-I', '-c', receiver, str(os.geteuid()),
                             str(home), '5000'], env=dict(os.environ, HOME=str(home)),
                            input=payload, capture_output=True, timeout=15)
    if allowed:
        assert result.returncode == 0, (name, result.stderr.decode())
        assert (home / '.codex/auth.json').read_bytes() == payload, name
    else:
        assert result.returncode == 2, (name, 'unsafe home admitted', result.stdout.decode())
        assert not (home / '.codex').exists(), name
    print('ACL-CASE', name, 'accepted' if allowed else 'refused')
";
    let output = Command::new("/usr/bin/python3")
        .args(["-I", "-c", script])
        .arg(root.path())
        .arg(include_str!("../src/door_sign_in_private.py"))
        .output()
        .expect("real receiver ACL cases");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
