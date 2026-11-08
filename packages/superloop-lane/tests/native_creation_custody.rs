use loop_home::anchor::{
    self, Anchor, Kind, Manifest, ModePolicy, Owner, Policy, Receiver, Requirement, Transport,
};
use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::path::Path;
const OPERATION: &str = "make-home";
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;
const CHILD: &str = "SUPERLOOP_NATIVE_CUSTODY_TEST";

/// # Panics
/// Panics if the namespace fixture cannot create or clean mapped private custody.
fn fixture_python(home: &Path, script: &str) {
    let output = Command::new("/usr/bin/podman")
        .args(["unshare", "/usr/bin/python3", "-I", "-c", script])
        .arg(home)
        .output()
        .expect("namespace fixture");
    assert!(
        output.status.success(),
        "unmeasured namespace fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
/// # Panics
/// Panics if mapped storage or configuration cannot be prepared.
fn fixture(home: &Path) {
    for path in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
        home.join("runs"),
    ] {
        fs::create_dir_all(&path).expect("directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("directory mode");
    }
    for (name, source) in [
        (
            "registry.toml",
            "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{name='alpha',uid=64000,launch='dev/alpha'}]\n",
        ),
        (
            "allocations.toml",
            "mail_uid=64001\n[alpha]\nuids={base=64010,count=2}\nmail_gids={base=64020,count=3}\n",
        ),
    ] {
        let path = home.join(".config/loops").join(name);
        fs::write(&path, source).expect("configuration");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("file mode");
    }
    fixture_python(
        home,
        r"
import os,sys
from pathlib import Path
home=Path(sys.argv[1])
assert os.geteuid()==0
assert os.stat('/').st_uid==int(Path('/proc/sys/kernel/overflowuid').read_text())
for path,uid,mode in [(home/'.var',0,0o711),(home/'.var/loops',0,0o711),(home/'.var/loops/alpha',0,0o711),(home/'.var/loops/alpha/private',64000,0o700)]:
 path.mkdir()
 os.chmod(path,mode)
 os.chown(path,uid,uid)
private=home/'.var/loops/alpha/private'
for path in [private/'.config',private/'.config/mail']:
 path.mkdir()
 os.chmod(path,0o700)
 os.chown(path,64000,64000)
config=private/'.config/mail/loop.toml'
config.write_text('workers=[]\n[mail]\nversion=1\nallow=[]\n')
os.chmod(config,0o600)
os.chown(config,64000,64000)
",
    );
}
fn requirements(owner: u32) -> Vec<Requirement> {
    let purposes = [
        "owner-home",
        "runs-root",
        "entry-executable",
        "podman-executable",
        "hash-executable",
        "configuration",
        "loop-storage",
        "private-storage",
        "identity-executable",
        "credential-client",
        "credential-clock",
        "letter-directory",
    ];
    purposes
        .iter()
        .enumerate()
        .map(|(slot, purpose)| Requirement {
            purpose: (*purpose).into(),
            alias_group: matches!(slot, 0 | 1 | 11).then(|| "launch-directory".into()),
            policy: match slot {
                0 | 1 | 5 | 11 => Policy {
                    kind: Kind::Directory,
                    owner: Owner::Host,
                    mode: ModePolicy::Exact(0o700),
                },
                6 => Policy {
                    kind: Kind::Directory,
                    owner: Owner::Host,
                    mode: ModePolicy::Exact(0o711),
                },
                7 => Policy {
                    kind: Kind::Directory,
                    owner: Owner::Mapped(owner),
                    mode: ModePolicy::Exact(0o700),
                },
                _ => Policy {
                    kind: Kind::File,
                    owner: if slot == 2 {
                        Owner::Host
                    } else {
                        Owner::RootFile
                    },
                    mode: ModePolicy::Executable,
                },
            },
        })
        .collect::<Vec<_>>()
}
/// # Panics
/// Panics if held native storage cannot reserve, finish and verify the same lifetime.
fn child(home: &str, manifest: &str) {
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(nix::unistd::Uid::effective().as_raw(), 0);
    let overflow = fs::read_to_string("/proc/sys/kernel/overflowuid")
        .expect("overflow uid")
        .trim()
        .parse::<u32>()
        .expect("numeric uid");
    assert_eq!(fs::metadata("/").expect("root").uid(), overflow);
    let declaration = Manifest::parse(manifest).expect("manifest");
    let input = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .expect("input");
    let descriptors = anchor::transport::receive(
        &std::os::unix::net::UnixStream::from(input),
        12,
        std::time::Duration::from_secs(30),
    )
    .expect("complete rights");
    anchor::transport::replace_stdin(OPERATION).expect("null stdin");
    let receiver = Receiver::current().expect("receiver map");
    let home = Path::new(home);
    let configuration = receiver
        .configuration(
            &declaration,
            &descriptors,
            anchor::Entry {
                operation: OPERATION,
                loop_name: "alpha",
                transport: Transport::Rights,
            },
            home,
            false,
        )
        .expect("anchored configuration");
    let required = requirements(
        configuration
            .registry
            .row("alpha", home)
            .expect("grant")
            .uid,
    );
    let anchors = receiver
        .validate(
            &declaration,
            descriptors,
            OPERATION,
            "alpha",
            Transport::Rights,
            &required,
        )
        .expect("validated capabilities");
    let root: &Anchor = &anchors[6];
    let private = &anchors[7];
    let executor = &anchors[8];
    exercise_phases(home, &configuration, root, private, executor);
}
/// # Panics
/// Panics if native receipt phases or registry-override refusals differ from their contract.
fn exercise_phases(
    home: &Path,
    configuration: &anchor::Configuration,
    root: &Anchor,
    private: &Anchor,
    executor: &Anchor,
) {
    let identity = loop_home::mail::birth::Identity::for_reservation(
        64010,
        "superloop-lane:native-custody".into(),
    );
    if std::env::var_os("ENTER_LOOP_REGISTRY").is_some() {
        let error = loop_home::mail::worker_provision::verify_beneath(
            home,
            "alpha",
            &identity,
            configuration,
            root,
            private,
            executor,
        )
        .expect_err("ambient registry is refused even when canonical");
        assert!(
            error.to_string().contains(
                "anchor-declaration: operation=prepare-runtime purpose=registry-override"
            ),
            "{error}"
        );
        return;
    }
    let census = || {
        loop_home::mail::worker_provision::reserved_uids_beneath(home, "alpha", configuration, root)
            .expect("census beneath renamed configuration and storage")
    };
    assert!(census().is_empty(), "fresh native history");
    for phase in ["reserve", "finish"] {
        loop_home::mail::worker_provision::creation_beneath(
            home,
            "alpha",
            &identity,
            phase,
            configuration,
            root,
            private,
            executor,
        )
        .expect("anchored creation phase");
        assert_eq!(census(), std::collections::BTreeSet::from([identity.uid]));
    }
    census_refusals(home, configuration, root, identity.uid);
    loop_home::mail::worker_provision::verify_beneath(
        home,
        "alpha",
        &identity,
        configuration,
        root,
        private,
        executor,
    )
    .expect("anchored verification");
    assert!(
        loop_home::mail::worker_provision::creation_beneath(
            home,
            "alpha",
            &identity,
            "retire",
            configuration,
            root,
            private,
            executor
        )
        .expect_err("creation cannot retire")
        .to_string()
        .contains("unknown creation phase")
    );
}
/// # Panics
/// Panics if missing receipts, malformed receipts or linked history bypass the held census.
fn census_refusals(home: &Path, configuration: &anchor::Configuration, root: &Anchor, uid: u32) {
    let storage = home.join(".var/loops/held-alpha");
    let births = storage.join(".mail-births");
    let hidden = storage.join("held-births");
    let census = || {
        loop_home::mail::worker_provision::reserved_uids_beneath(home, "alpha", configuration, root)
    };
    fs::rename(&births, &hidden).expect("hold receipts aside");
    assert!(
        census()
            .expect_err("worker history requires receipts")
            .to_string()
            .contains("worker history requires reconciliation")
    );
    fs::rename(&hidden, &births).expect("restore receipts");
    let stray = births.join("unexpected.toml");
    fs::write(&stray, b"not a receipt").expect("malformed receipt");
    fs::set_permissions(&stray, fs::Permissions::from_mode(0o600)).expect("receipt mode");
    assert!(
        census()
            .expect_err("malformed receipt refuses")
            .to_string()
            .contains("worker birth receipt")
    );
    fs::remove_file(&stray).expect("restore receipts");
    let workers = storage.join("workers");
    let held = storage.join("held-workers");
    fs::rename(&workers, &held).expect("hold worker history");
    std::os::unix::fs::symlink(&held, &workers).expect("linked history");
    assert!(
        census().is_err(),
        "history links cannot redirect the census"
    );
    fs::remove_file(&workers).expect("remove history link");
    fs::rename(&held, &workers).expect("restore history");
    assert_eq!(
        census().expect("restored held census"),
        std::collections::BTreeSet::from([uid])
    );
}
/// # Panics
/// Panics if the production native composer loses storage or executable custody across Podman.
fn native_creation_reserves_and_finishes_beneath_custody() {
    if let Ok(home) = std::env::var(CHILD) {
        child(
            &home,
            &std::env::var("SUPERLOOP_NATIVE_MANIFEST").expect("declaration"),
        );
        return;
    }
    let directory = tempfile::tempdir().expect("home");
    let home = directory.path();
    fixture(home);
    let held_home = fs::File::open(home).expect("home").into();
    let runs = home.join("runs");
    let held_runs = fs::File::open(&runs).expect("runs").into();
    let image = std::env::current_exe().expect("test image");
    let argv = vec![
        "unshare".into(),
        image.to_str().expect("image word").into(),
        "_make-home".into(),
        "alpha".into(),
        "native-custody".into(),
        "--letter".into(),
        home.join("letter").to_str().expect("letter").into(),
        "--owner-home".into(),
        home.to_str().expect("home word").into(),
        "--worker-uid".into(),
        "64010".into(),
        "--podman-bin".into(),
        "/usr/bin/podman".into(),
        "--model".into(),
        "model".into(),
        "--effort".into(),
        "high".into(),
        "--model-source".into(),
        "argument".into(),
        "--effort-source".into(),
        "argument".into(),
        "--door-scope".into(),
        "work".into(),
    ];
    let requests = (0..3)
        .map(|_| {
            superloop_lane::creation_entry::command(
                Path::new("/usr/bin/podman"),
                &argv,
                (home, &held_home),
                (&runs, &held_runs),
                (home, &held_home),
                None,
            )
            .expect("production composer")
        })
        .collect::<Vec<_>>();
    fs::rename(home.join(".config/loops"), home.join(".config/held-loops"))
        .expect("replace configuration path after pin");
    fs::rename(
        home.join(".var/loops/alpha"),
        home.join(".var/loops/held-alpha"),
    )
    .expect("replace storage path after pin");
    for (request, registry) in requests.into_iter().zip([
        None,
        Some(home.join(".config/loops/registry.toml")),
        Some(home.join("absent-registry")),
    ]) {
        run_child(home, &image, &request, registry.as_deref());
    }
    fixture_python(
        home,
        "import shutil,sys; shutil.rmtree(sys.argv[1]+'/.var')",
    );
}

/// # Panics
/// Panics if the anchored namespace child fails its selected registry policy.
fn run_child(home: &Path, image: &Path, request: &loop_home::CommandSpec, registry: Option<&Path>) {
    let mut process = Command::new("/usr/bin/podman");
    process.args(["unshare"]).arg(image).env(CHILD, home).env(
        "SUPERLOOP_NATIVE_MANIFEST",
        request.argv.last().expect("manifest"),
    );
    request
        .descriptors
        .configure(&mut process)
        .expect("rights transport");
    if let Some(registry) = registry {
        process.env("ENTER_LOOP_REGISTRY", registry);
    }
    let output = process.output().expect("namespace entry");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("native custody passed"));
}

fn main() -> std::process::ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|word| {
        word.to_str()
            .is_some_and(|word| word.starts_with("_mail-worker-"))
    }) {
        return std::process::ExitCode::from(loop_home::mail::worker_provision::entry(
            &args,
            &mut std::io::stderr().lock(),
        ));
    }
    native_creation_reserves_and_finishes_beneath_custody();
    std::io::stdout()
        .write_all(b"native custody passed\n")
        .expect("fixture report");
    std::process::ExitCode::SUCCESS
}
