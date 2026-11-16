//! Fresh named pipes with keeper writers; no plaintext read or write API.
use super::{
    Result,
    measure::{Admission, ObjectIdentity},
    require,
    store::Directory,
};
use crate::receipt;
use nix::fcntl::{FcntlArg, OFlag, fcntl, openat};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::unistd::{UnlinkatFlags, mkfifoat, unlinkat};
use serde::Serialize;
use std::fs::{File, Permissions};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;

#[derive(Serialize)]
struct Entry {
    name: &'static str,
    object: ObjectIdentity,
}
struct Pipe {
    reader: File,
    keeper: Option<OwnedFd>,
    entry: Entry,
}
pub(super) struct Pipes {
    directory: Directory,
    ends: [Pipe; 2],
    paths: [PathBuf; 2],
    released: bool,
    uncertain: bool,
}
impl Pipes {
    pub const fn directory(&self) -> &Directory {
        &self.directory
    }
    pub fn create(admission: &Admission, index: usize) -> Result<Self> {
        let case = admission
            .policy()
            .cases
            .get(index)
            .ok_or("launch-case-binding")?;
        let root = &admission.policy().roots.runtime;
        let directory = Directory::create(root, &case.id)?;
        let pipes = [
            Pipe::create(directory.file(), "left.fifo")?,
            Pipe::create(directory.file(), "right.fifo")?,
        ];
        directory.verify()?;
        let manifest = serde_json::to_vec(&serde_json::json!({"schema":1,"case":case.id,"objects":[&pipes[0].entry,&pipes[1].entry]})).map_err(|_| "fifo-manifest")?;
        receipt::publish_held(directory.file(), "fifo-manifest.json", &manifest)?;
        Ok(Self {
            directory,
            ends: pipes,
            paths: [
                root.join(&case.id).join("left.fifo"),
                root.join(&case.id).join("right.fifo"),
            ],
            released: false,
            uncertain: false,
        })
    }
    pub const fn identities(&self) -> [ObjectIdentity; 2] {
        [self.ends[0].entry.object, self.ends[1].entry.object]
    }
    pub const fn paths(&self) -> &[PathBuf; 2] {
        &self.paths
    }
    pub fn readers(&self) -> Result<[OwnedFd; 2]> {
        self.verify()?;
        Ok([
            self.ends[0]
                .reader
                .try_clone()
                .map_err(|_| "fifo-duplicate")?
                .into(),
            self.ends[1]
                .reader
                .try_clone()
                .map_err(|_| "fifo-duplicate")?
                .into(),
        ])
    }
    fn verify(&self) -> Result<()> {
        require(!self.released && !self.uncertain, "fifo-terminal")?;
        self.directory.verify()?;
        for pipe in &self.ends {
            pipe.verify(self.directory.file())?;
        }
        Ok(())
    }
    // The external descriptor observer supplies held copies of the two actual
    // fixture slots. Mere manager success or a declared inode is not capture.
    pub fn capture(&mut self, writers: [&File; 2]) -> Result<()> {
        require(!self.released && !self.uncertain, "fifo-terminal")?;
        let result = (|| {
            self.verify()?;
            for (pipe, writer) in self.ends.iter().zip(writers) {
                let flags = fcntl(writer, FcntlArg::F_GETFL).map_err(|_| "fifo-writer-binding")?;
                let stat = fstat(writer).map_err(|_| "fifo-writer-binding")?;
                require(
                    ObjectIdentity::of(writer)? == pipe.entry.object
                        && SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFIFO)
                        && flags & OFlag::O_ACCMODE.bits() == OFlag::O_WRONLY.bits(),
                    "fifo-writer-binding",
                )?;
            }
            // Verify the entire set before either unlink; any partial failure
            // remains quarantine, never a new attempt under this case name.
            for pipe in &self.ends {
                unlinkat(
                    self.directory.file(),
                    pipe.entry.name,
                    UnlinkatFlags::NoRemoveDir,
                )
                .map_err(|_| "fifo-unlink")?;
            }
            self.directory.file().sync_all().map_err(|_| "fifo-sync")?;
            Ok(())
        })();
        if result.is_err() {
            self.uncertain = true;
            return result;
        }
        for pipe in &mut self.ends {
            drop(pipe.keeper.take());
        }
        self.released = true;
        Ok(())
    }
    // Explicit failed-case cleanup only. Never scan a root or unlink a foreign
    // replacement, and leave the immutable creation manifest for investigation.
    pub fn cleanup(&mut self) -> Result<()> {
        require(!self.released, "fifo-terminal")?;
        self.directory.verify()?;
        for pipe in &self.ends {
            pipe.verify(self.directory.file())?;
        }
        for pipe in &self.ends {
            unlinkat(
                self.directory.file(),
                pipe.entry.name,
                UnlinkatFlags::NoRemoveDir,
            )
            .map_err(|_| "fifo-unlink")?;
        }
        self.directory.file().sync_all().map_err(|_| "fifo-sync")?;
        for pipe in &mut self.ends {
            drop(pipe.keeper.take());
        }
        self.released = true;
        Ok(())
    }
}
impl Pipe {
    fn create(directory: &File, name: &'static str) -> Result<Self> {
        mkfifoat(directory, name, Mode::from_bits_truncate(0o600)).map_err(|_| "fifo-exclusive")?;
        let reader = File::from(
            openat(
                directory,
                name,
                OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "fifo-open")?,
        );
        reader
            .set_permissions(Permissions::from_mode(0o600))
            .map_err(|_| "fifo-mode")?;
        let keeper = openat(
            directory,
            name,
            OFlag::O_WRONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "fifo-keeper")?;
        fcntl(&reader, FcntlArg::F_SETFL(OFlag::empty())).map_err(|_| "fifo-blocking")?;
        let object = ObjectIdentity::of(&reader)?;
        let pipe = Self {
            reader,
            keeper: Some(keeper),
            entry: Entry { name, object },
        };
        pipe.verify(directory)?;
        Ok(pipe)
    }
    fn verify(&self, directory: &File) -> Result<()> {
        let current = File::from(
            openat(
                directory,
                self.entry.name,
                OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "fifo-binding")?,
        );
        let m = current.metadata().map_err(|_| "fifo-binding")?;
        require(
            ObjectIdentity::of(&current)? == self.entry.object
                && m.mode() & 0o170_000 == 0o010_000
                && m.mode() & 0o7777 == 0o600
                && m.uid() == nix::unistd::geteuid().as_raw()
                && m.nlink() == 1,
            "fifo-binding",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launch::{
        channel::{Input, PipeState},
        sealer::Session,
        sealer_tests::make_fixture,
        store::Store,
        tests::Fixture,
    };
    use std::fs;
    use std::io::Write as _;
    fn writers(pipes: &Pipes) -> [File; 2] {
        pipes
            .paths()
            .each_ref()
            .map(|path| fs::OpenOptions::new().write(true).open(path).unwrap())
    }
    /// ´test:unit:fifo-keeper-prevents-initial-eof-until-captured-writers´
    #[test]
    fn fifo_keeper_prevents_initial_eof_until_captured_writers() {
        let _case = crate::launch::test_support::case_guard();
        let fixture = make_fixture("normal");
        let admission = fixture.admit();
        let mut pipes = Pipes::create(&admission, 0).unwrap();
        let [left, right] = pipes.readers().unwrap();
        let (_, left_probe) = Input::admit(left).unwrap().split().unwrap();
        let (_, right_probe) = Input::admit(right).unwrap().split().unwrap();
        // No fixture writer exists yet. The kept writers make EOF impossible by
        // construction; no startup timing assumption or reader thread is used.
        assert_eq!(left_probe.observe().unwrap(), PipeState::Open);
        assert_eq!(right_probe.observe().unwrap(), PipeState::Open);
        assert_eq!(pipes.ends.iter().filter(|p| p.keeper.is_some()).count(), 2);
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut session =
            Session::start(&admission, 0, &mut store, pipes.readers().unwrap()).unwrap();
        let mut peers = writers(&pipes);
        pipes.capture([&peers[0], &peers[1]]).unwrap();
        assert_eq!(pipes.ends.iter().filter(|p| p.keeper.is_some()).count(), 0);
        assert_eq!(pipes.paths().iter().filter(|p| p.exists()).count(), 0);
        assert_eq!(pipes.capture([&peers[0], &peers[1]]), Err("fifo-terminal"));
        for peer in &mut peers {
            peer.write_all(b"synthetic").unwrap();
        }
        drop(peers);
        assert_eq!(
            session
                .wait_until(std::time::Instant::now() + std::time::Duration::from_secs(600))
                .unwrap()
                .sealed_bytes,
            [13, 13]
        );
        let manifest = fixture.dir.path().join("runtime/sample/fifo-manifest.json");
        assert_eq!(fs::metadata(&manifest).unwrap().mode() & 0o7777, 0o400);
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
        assert_eq!(value["objects"].as_array().unwrap().len(), 2);
    }
    /// ´test:unit:fifo-capture-refuses-wrong-writers-and-latches´
    #[test]
    fn fifo_capture_refuses_wrong_writers_and_latches() {
        let _case = crate::launch::test_support::case_guard();
        for kind in ["repeat", "reader", "regular"] {
            let fixture = Fixture::new();
            let admission = fixture.admit();
            let mut pipes = Pipes::create(&admission, 0).unwrap();
            let peers = writers(&pipes);
            let wrong = match kind {
                "repeat" => peers[0].try_clone().unwrap(),
                "reader" => pipes.ends[1].reader.try_clone().unwrap(),
                _ => tempfile::tempfile().unwrap(),
            };
            assert_eq!(
                pipes.capture([&peers[0], &wrong]),
                Err("fifo-writer-binding"),
                "{kind}"
            );
            assert_eq!(pipes.capture([&peers[0], &peers[1]]), Err("fifo-terminal"));
            assert_eq!(pipes.paths().iter().filter(|p| p.exists()).count(), 2);
            pipes.cleanup().unwrap();
        }
    }
    /// ´test:unit:fifo-custody-is-exclusive-and-cleanup-verifies-all-objects´
    #[test]
    fn fifo_custody_is_exclusive_and_cleanup_verifies_all_objects() {
        let _case = crate::launch::test_support::case_guard();
        for kind in ["replace", "mode", "link", "directory"] {
            let fixture = Fixture::new();
            let admission = fixture.admit();
            let mut pipes = Pipes::create(&admission, 0).unwrap();
            assert_eq!(
                Pipes::create(&admission, 0).err(),
                Some("launch-exclusive-directory")
            );
            let peers = writers(&pipes);
            let path = pipes.paths()[1].clone();
            let saved = path.with_extension("saved");
            match kind {
                "replace" => {
                    fs::rename(&path, &saved).unwrap();
                    nix::unistd::mkfifo(&path, Mode::from_bits_truncate(0o600)).unwrap();
                }
                "mode" => fs::set_permissions(&path, Permissions::from_mode(0o666)).unwrap(),
                "link" => fs::hard_link(&path, &saved).unwrap(),
                _ => fs::set_permissions(path.parent().unwrap(), Permissions::from_mode(0o777))
                    .unwrap(),
            }
            let class = if kind == "directory" {
                "launch-directory-binding"
            } else {
                "fifo-binding"
            };
            assert_eq!(pipes.capture([&peers[0], &peers[1]]), Err(class));
            assert_eq!(pipes.cleanup(), Err(class));
            assert!(pipes.paths()[0].exists());
            match kind {
                "replace" => {
                    assert_ne!(
                        fs::metadata(&path).unwrap().ino(),
                        fs::metadata(&saved).unwrap().ino()
                    );
                    fs::remove_file(&path).unwrap();
                    fs::rename(saved, &path).unwrap();
                }
                "mode" => fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap(),
                "link" => fs::remove_file(saved).unwrap(),
                _ => fs::set_permissions(path.parent().unwrap(), Permissions::from_mode(0o700))
                    .unwrap(),
            }
            assert_eq!(pipes.capture([&peers[0], &peers[1]]), Err("fifo-terminal"));
            pipes.cleanup().unwrap();
            assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        }
    }
}
