#[path = "../../support/temporary_root.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "support is compiled both independently and alongside status support in library tests"
)]
mod temporary_root;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub struct TestDir {
    path: PathBuf,
}

impl TestDir {
    #[must_use]
    pub fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = temporary_root::temporary_root().join(format!(
            "worker-monitor-test-{}-{sequence}-{label}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create isolated test directory");
        Self { path }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write(&self, name: impl AsRef<OsStr>, bytes: &[u8]) {
        std::fs::write(self.path.join(name.as_ref()), bytes).expect("write fixture file");
    }

    pub fn set_modified(&self, name: impl AsRef<OsStr>, modified: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(self.path.join(name.as_ref()))
            .expect("open fixture for timestamp control")
            .set_modified(modified)
            .expect("set fixture modification time");
    }

    pub fn mkdir(&self, name: impl AsRef<OsStr>) {
        std::fs::create_dir(self.path.join(name.as_ref())).expect("create fixture directory");
    }

    #[must_use]
    pub fn read(&self, name: impl AsRef<OsStr>) -> Vec<u8> {
        std::fs::read(self.path.join(name.as_ref())).expect("read fixture file")
    }

    #[must_use]
    pub fn exists(&self, name: impl AsRef<OsStr>) -> bool {
        self.path.join(name.as_ref()).exists()
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "remove isolated test directory: {error}"
            );
        }
    }
}
