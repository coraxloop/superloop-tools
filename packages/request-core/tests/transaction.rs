use std::fs::{self, File};
use std::os::unix::fs::{PermissionsExt as _, symlink};

use request_core::transaction::{Transaction, read};

/// ´test:integration:transaction-refuses-identical-bytes-on-a-replaced-inode´
#[test]
fn transaction_refuses_identical_bytes_on_a_replaced_inode() {
    let directory = tempfile::tempdir().expect("directory");
    let descriptor = File::open(directory.path()).expect("descriptor");
    let mut transaction = Transaction::open(&descriptor, "collection", "lock").expect("lock");
    transaction.replace(b"same bytes").expect("publish");
    let replacement = directory.path().join("replacement");
    fs::write(&replacement, b"same bytes").expect("replacement");
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
        .expect("private replacement");
    fs::rename(replacement, directory.path().join("collection")).expect("replace inode");
    assert!(transaction.replace(b"must not publish").is_err());
    assert_eq!(
        fs::read(directory.path().join("collection")).expect("retained"),
        b"same bytes"
    );
}

/// ´test:integration:transaction-snapshots-are-read-only-and-refused-staging-preserves-bytes´
#[test]
fn transaction_snapshots_are_read_only_and_refused_staging_preserves_bytes() {
    let directory = tempfile::tempdir().expect("directory");
    let descriptor = File::open(directory.path()).expect("descriptor");
    assert_eq!(read(&descriptor, "collection").expect("missing"), None);
    assert_eq!(fs::read_dir(directory.path()).expect("contents").count(), 0);
    let mut transaction = Transaction::open(&descriptor, "collection", "lock").expect("lock");
    transaction.replace(b"old").expect("publish");
    fs::write(directory.path().join("collection"), b"changed outside lock")
        .expect("external change");
    assert!(transaction.replace(b"new").is_err());
    assert_eq!(
        read(&descriptor, "collection").expect("snapshot"),
        Some(b"changed outside lock".to_vec())
    );
}

/// ´test:integration:transaction-refuses-symlinks-and-shared-file-custody´
#[test]
fn transaction_refuses_symlinks_and_shared_file_custody() {
    let directory = tempfile::tempdir().expect("directory");
    let descriptor = File::open(directory.path()).expect("descriptor");
    fs::write(directory.path().join("target"), b"retained").expect("target");
    symlink("target", directory.path().join("collection")).expect("symlink");
    assert!(Transaction::open(&descriptor, "collection", "lock").is_err());
    assert_eq!(
        fs::read(directory.path().join("target")).expect("target"),
        b"retained"
    );
    fs::remove_file(directory.path().join("collection")).expect("remove symlink");
    fs::write(directory.path().join("collection"), b"old").expect("record");
    fs::set_permissions(
        directory.path().join("collection"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("shared mode");
    assert!(read(&descriptor, "collection").is_err());
}

/// ´test:integration:transaction-lock-serializes-contending-terminal-writers´
#[test]
fn transaction_lock_serializes_contending_terminal_writers() {
    let directory = tempfile::tempdir().expect("directory");
    let mut threads = Vec::new();
    for _ in 0..8 {
        let path = directory.path().to_owned();
        threads.push(std::thread::spawn(move || {
            let descriptor = File::open(path).expect("descriptor");
            let mut transaction =
                Transaction::open(&descriptor, "collection", "lock").expect("lock");
            let value = transaction.bytes().map_or(0, |bytes| {
                std::str::from_utf8(bytes)
                    .expect("utf8")
                    .parse::<u32>()
                    .expect("count")
            });
            transaction
                .replace((value + 1).to_string().as_bytes())
                .expect("publish");
        }));
    }
    for thread in threads {
        thread.join().expect("writer");
    }
    assert_eq!(
        fs::read(directory.path().join("collection")).expect("record"),
        b"8"
    );
}
