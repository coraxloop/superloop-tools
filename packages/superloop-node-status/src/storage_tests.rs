use super::*;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct FixtureReader {
    identity: io::Result<FilesystemIdentity>,
    project_inherits: io::Result<bool>,
    counters: io::Result<Counters>,
    calls: Cell<usize>,
    interrupt: bool,
}

impl Reader for FixtureReader {
    type Handle = ();

    fn open(&self, _query: &Path) -> io::Result<Self::Handle> {
        Ok(())
    }

    fn identity(
        &self,
        _handle: &Self::Handle,
        _mount: &Path,
        _query: &Path,
    ) -> io::Result<FilesystemIdentity> {
        self.calls.set(self.calls.get() + 1);
        assert!(!self.interrupt, "interrupted after durable reservation");
        self.identity
            .as_ref()
            .cloned()
            .map_err(|error| io::Error::new(error.kind(), error.to_string()))
    }

    fn project_inherits(&self, _handle: &Self::Handle) -> io::Result<bool> {
        self.project_inherits
            .as_ref()
            .copied()
            .map_err(|error| io::Error::new(error.kind(), error.to_string()))
    }

    fn counters(&self, _handle: &Self::Handle) -> io::Result<Counters> {
        self.counters
            .as_ref()
            .copied()
            .map_err(|error| io::Error::new(error.kind(), error.to_string()))
    }
}

fn identity() -> FilesystemIdentity {
    FilesystemIdentity {
        major_minor: "7:2".to_owned(),
        filesystem_type: "xfs".to_owned(),
        source: "/dev/fixture".to_owned(),
    }
}

fn reader() -> FixtureReader {
    FixtureReader {
        identity: Ok(identity()),
        project_inherits: Ok(false),
        counters: Ok(Counters {
            fragment_size: 4096,
            blocks: 1000,
            blocks_free: 300,
            blocks_available: 250,
            files: 90,
            files_free: 40,
            files_available: 35,
        }),
        calls: Cell::new(0),
        interrupt: false,
    }
}

fn volume(id: &str, scope: CapacityScope) -> VolumeConfig {
    VolumeConfig {
        id: id.to_owned(),
        mount_path: PathBuf::from(format!("/fixture/{id}")),
        query_path: PathBuf::from(format!("/fixture/{id}")),
        identity: identity(),
        capacity_scope: scope,
    }
}

fn config() -> Config {
    Config {
        schema: 1,
        node_id: "fixture-node".to_owned(),
        incarnation_id: "first".to_owned(),
        configuration_revision: "one".to_owned(),
        reader_gid: nix::unistd::getgid().as_raw(),
        volumes: vec![
            volume("data", CapacityScope::Filesystem),
            volume("temporary", CapacityScope::ProjectScoped),
        ],
        accounts: vec![
            AccountConfig {
                account_id: "fixture-account".to_owned(),
                uid: 3000,
                storage_class: "home".to_owned(),
                volume_id: "data".to_owned(),
                project_id: None,
                collection_enabled: true,
            },
            AccountConfig {
                account_id: "fixture-account".to_owned(),
                uid: 3000,
                storage_class: "temporary".to_owned(),
                volume_id: "temporary".to_owned(),
                project_id: Some(3000),
                collection_enabled: true,
            },
        ],
    }
}

/// # Panics
/// Panics if a stacked mount selects its lower entry, a descriptor on another device is accepted, or a query link is followed.
/// ´test:unit:storage-kernel-reader-verifies-opened-directory´
#[test]
fn storage_kernel_reader_verifies_opened_directory() {
    let root = tempfile::tempdir().expect("fixture directory");
    let handle = KernelReader
        .open(root.path())
        .expect("one directory descriptor");
    let device = handle.metadata().expect("descriptor metadata").dev();
    let major_minor = format!(
        "{}:{}",
        nix::sys::stat::major(device),
        nix::sys::stat::minor(device)
    );
    let mounts = format!(
        "1 0 {major_minor} / /fixture rw - xfs /dev/lower rw\n2 1 {major_minor} / /fixture rw - xfs /dev/top rw\n"
    );
    let selected = KernelReader::identity_from_mountinfo(
        &mounts,
        &handle,
        Path::new("/fixture"),
        Path::new("/fixture/query"),
    )
    .expect("topmost stacked mount");
    assert_eq!(selected.source, "/dev/top");
    assert_eq!(selected.major_minor, major_minor);
    let wrong = mounts.replace(&major_minor, "999:999");
    assert!(
        KernelReader::identity_from_mountinfo(
            &wrong,
            &handle,
            Path::new("/fixture"),
            Path::new("/fixture/query"),
        )
        .expect_err("descriptor device must agree")
        .to_string()
        .contains("descriptor device differs")
    );
    assert!(
        KernelReader::identity_from_mountinfo(
            &mounts,
            &handle,
            Path::new("/missing-mount"),
            Path::new("/fixture/query"),
        )
        .expect_err("missing configured mount")
        .to_string()
        .contains("mount absent")
    );
    let link = root.path().with_extension("query-link");
    std::os::unix::fs::symlink(root.path(), &link).expect("fixture link");
    assert!(KernelReader.open(&link).is_err());
    fs::remove_file(link).expect("remove fixture link");
}

/// # Panics
/// Panics if a group-writable or non-root-owned configuration reaches sampling.
/// ´test:unit:storage-config-custody-precedes-sampling´
#[test]
fn storage_config_custody_precedes_sampling() {
    let root = tempfile::tempdir().expect("fixture root");
    let path = root.path().join("node-storage.json");
    fs::write(&path, b"{}").expect("fixture configuration");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
    let metadata = fs::metadata(&path).expect("fixture metadata");
    check_config_custody(&metadata, nix::unistd::geteuid().as_raw()).expect("owned fixture");
    if nix::unistd::geteuid().as_raw() != 0 {
        assert!(
            load_config(&path)
                .expect_err("a non-root configuration cannot reach a kernel read")
                .to_string()
                .contains("configuration-custody")
        );
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).expect("writable mode");
    assert!(
        check_config_custody(
            &fs::metadata(&path).expect("changed metadata"),
            nix::unistd::geteuid().as_raw(),
        )
        .expect_err("group write must refuse")
        .to_string()
        .contains("configuration-custody")
    );
}

/// # Panics
/// Panics if counter units change or an absent, wrong, unreadable or project-scoped volume is reported as zero capacity.
/// ´test:unit:storage-counters-and-null-errors´
#[test]
fn storage_counters_and_null_errors() {
    let known = read_volume(
        &volume("data", CapacityScope::Filesystem),
        &reader(),
        "boot",
    )
    .expect("known counters");
    assert_eq!(known.total_bytes, Some(4_096_000));
    assert_eq!(known.free_bytes, Some(1_228_800));
    assert_eq!(known.available_bytes, Some(1_024_000));
    assert_eq!(known.total_inodes, Some(90));
    assert_eq!(known.free_inodes, Some(40));
    assert_eq!(known.available_inodes, Some(35));

    let mut missing = reader();
    missing.identity = Err(bad("mount absent"));
    let mut wrong = reader();
    wrong.identity = Ok(FilesystemIdentity {
        source: "/dev/wrong".to_owned(),
        ..identity()
    });
    let mut unreadable = reader();
    unreadable.counters = Err(io::Error::other("fixture read failed"));
    for (fixture, kind) in [
        (&missing, "mount_absent"),
        (&wrong, "identity_mismatch"),
        (&unreadable, "counter_read_failed"),
    ] {
        let row = read_volume(&volume("data", CapacityScope::Filesystem), fixture, "boot")
            .expect("typed failed reading");
        assert_eq!(row.error.as_deref(), Some(kind));
        assert_eq!(row.total_bytes, None);
        assert_eq!(row.free_bytes, None);
        assert_eq!(row.available_bytes, None);
    }
    let scoped = reader();
    let row = read_volume(
        &volume("tmp", CapacityScope::ProjectScoped),
        &scoped,
        "boot",
    )
    .expect("scoped reading");
    assert_eq!(row.status, "unmeasured");
    assert_eq!(row.error.as_deref(), Some("project_scoped_query"));
    assert_eq!(row.total_bytes, None);
    assert_eq!(scoped.calls.get(), 1);
    let inherited = FixtureReader {
        project_inherits: Ok(true),
        ..reader()
    };
    let row = read_volume(
        &volume("tmp", CapacityScope::Filesystem),
        &inherited,
        "boot",
    )
    .expect("kernel project flag wins over configuration");
    assert_eq!(row.error.as_deref(), Some("project_scoped_query"));
    assert_eq!(row.total_bytes, None);
    let unknown = FixtureReader {
        project_inherits: Err(io::Error::from_raw_os_error(libc::ENOTTY)),
        ..reader()
    };
    let row = read_volume(&volume("tmp", CapacityScope::Filesystem), &unknown, "boot")
        .expect("unknown project scope is not a volume capacity");
    assert_eq!(row.status, "failed");
    assert_eq!(row.error.as_deref(), Some("project_attribute_unavailable"));
    assert_eq!(row.total_bytes, None);
}

/// # Panics
/// Panics if a duplicate, interrupted or backwards attempt takes a second daily slot or overwrites a sample.
/// ´test:unit:storage-daily-attempt-custody´
#[test]
fn storage_daily_attempt_custody() {
    let root = tempfile::tempdir().expect("fixture root");
    let config = config();
    let base = now_ns().expect("clock") / 86_400_000_000_000 * 86_400_000_000_000;
    let yesterday = base - 60_000_000_000;
    let today = base + 60_000_000_000;
    let first =
        sample_once(&config, root.path(), &reader(), yesterday, "boot").expect("late catch-up");
    assert_eq!(first.sequence, 1);
    assert_eq!(first.state_nonce.len(), 36);
    assert_eq!(first.accounts[0].coverage, "unmarked");
    assert_eq!(first.accounts[0].charged_bytes, None);
    assert_eq!(first.volumes.len(), 2);
    assert_eq!(first.volumes[0].status, "complete");
    assert_eq!(first.volumes[1].status, "unmeasured");
    assert_eq!(first.volumes[1].total_bytes, None);
    assert_eq!(first.accounts[1].project_id, Some(3000));
    assert_eq!(first.accounts[1].coverage, "unmarked");
    assert_eq!(
        fs::metadata(root.path().join("samples/00000000000000000001.json"))
            .unwrap()
            .gid(),
        config.reader_gid
    );
    let first_bytes =
        fs::read(root.path().join("samples/00000000000000000001.json")).expect("published sample");
    assert!(sample_once(&config, root.path(), &reader(), yesterday, "boot").is_err());
    let second = sample_once(&config, root.path(), &reader(), today, "boot")
        .expect("next UTC date without a 24-hour minimum");
    assert_eq!(second.sequence, 2);
    assert_eq!(second.state_nonce, first.state_nonce);
    assert!(sample_once(&config, root.path(), &reader(), yesterday, "boot").is_err());
    assert_eq!(
        fs::read(root.path().join("samples/00000000000000000001.json")).unwrap(),
        first_bytes
    );
    let interrupted = FixtureReader {
        interrupt: true,
        ..reader()
    };
    let tomorrow = today + 86_400_000_000_000;
    let stopped = catch_unwind(AssertUnwindSafe(|| {
        let _result = sample_once(&config, root.path(), &interrupted, tomorrow, "boot");
    }));
    assert!(stopped.is_err());
    assert!(sample_once(&config, root.path(), &reader(), tomorrow, "boot").is_err());
    assert_eq!(root.path().join("attempts").read_dir().unwrap().count(), 3);
    assert_eq!(root.path().join("samples").read_dir().unwrap().count(), 2);
    let page: serde_json::Value = serde_json::from_slice(&export(root.path(), 0, 16).unwrap())
        .expect("unfinished attempt page");
    assert_eq!(page["unfinished_attempts"].as_array().unwrap().len(), 1);
    assert_eq!(page["unfinished_attempts"][0]["sequence"], 3);
    assert_eq!(
        page["unfinished_attempts"][0]["scheduled_date"],
        utc_date(tomorrow).expect("date")
    );
    assert_eq!(page["state_nonce"], first.state_nonce);
    let replacement = tempfile::tempdir().expect("replacement state root");
    let restarted = sample_once(&config, replacement.path(), &reader(), today, "boot")
        .expect("first sample after state replacement");
    assert_eq!(restarted.sequence, 1);
    assert_ne!(restarted.state_nonce, first.state_nonce);
    let replaced_page: serde_json::Value = serde_json::from_slice(
        &export(replacement.path(), 99, 2).expect("beyond-end replacement page"),
    )
    .expect("replacement export");
    assert_eq!(replaced_page["state_nonce"], restarted.state_nonce);
}

/// # Panics
/// Panics if a second start reads the kernel while an earlier sampler holds the state lock.
/// ´test:unit:storage-sampler-refuses-overlapping-start´
#[test]
fn storage_sampler_refuses_overlapping_start() {
    let root = tempfile::tempdir().expect("fixture root");
    let config = config();
    ensure_dir(root.path(), 0o750, config.reader_gid).expect("state root");
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.path().join("sample.lock"))
        .expect("lock file");
    let held = Flock::lock(lock, FlockArg::LockExclusive).expect("first sampler");
    let reader = reader();
    let started = now_ns().expect("clock");
    let refusal = sample_once(&config, root.path(), &reader, started, "boot")
        .expect_err("second sampler must refuse");
    assert!(refusal.to_string().contains("sample busy"));
    assert_eq!(reader.calls.get(), 0);
    drop(held);
    assert!(sample_once(&config, root.path(), &reader, started, "boot").is_ok());
}

/// # Panics
/// Panics if the export skips a kept sequence, exceeds its page count or treats beyond-end as a refusal.
/// ´test:unit:storage-export-pages-are-complete´
#[test]
fn storage_export_pages_are_complete() {
    let root = tempfile::tempdir().expect("fixture root");
    let config = config();
    let base = now_ns().expect("clock") / 86_400_000_000_000 * 86_400_000_000_000;
    for day in 0..3 {
        sample_once(
            &config,
            root.path(),
            &reader(),
            base - (2 - day) * 86_400_000_000_000,
            "boot",
        )
        .expect("sample");
    }
    let first_bytes = export(root.path(), 0, 2).unwrap();
    assert!(first_bytes.len() <= MAX_PAGE_BYTES);
    let first: serde_json::Value = serde_json::from_slice(&first_bytes).expect("first page");
    assert_eq!(first["samples"].as_array().unwrap().len(), 2);
    assert_eq!(first["next_after_sequence"], 2);
    assert_eq!(first["has_more"], true);
    let next: serde_json::Value =
        serde_json::from_slice(&export(root.path(), 2, 2).unwrap()).expect("next page");
    assert_eq!(next["samples"][0]["sequence"], 3);
    assert_eq!(next["has_more"], false);
    let beyond: serde_json::Value =
        serde_json::from_slice(&export(root.path(), 99, 2).unwrap()).expect("beyond end");
    assert_eq!(beyond["samples"].as_array().unwrap().len(), 0);
    assert_eq!(beyond["next_after_sequence"], 99);
}
