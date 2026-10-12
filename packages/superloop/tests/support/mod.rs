use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn safe_fixture_path(path: &Path) -> Result<(), String> {
    let owner = (
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
    );
    let mut prefix = PathBuf::from("/");
    let mut parent = fs::symlink_metadata(&prefix).map_err(|error| error.to_string())?;
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err(String::from("a dotted component is present"));
        };
        prefix.push(name);
        let child = fs::symlink_metadata(&prefix).map_err(|error| error.to_string())?;
        if child.file_type().is_symlink() || !child.is_dir() {
            return Err(format!("{} is linked or not a directory", prefix.display()));
        }
        let mode = parent.mode() & 0o7777;
        if parent.uid() != 0 && parent.uid() != owner.0 {
            return Err(format!(
                "{} is owned by uid {}",
                prefix.display(),
                parent.uid()
            ));
        }
        if mode & 0o022 != 0 && (mode & 0o1000 == 0 || ![0, owner.0].contains(&child.uid())) {
            return Err(format!(
                "{} has replaceable parent mode {mode:04o}",
                prefix.display()
            ));
        }
        parent = child;
    }
    if parent.uid() != owner.0 || parent.gid() != owner.1 || parent.mode() & 0o7777 != 0o700 {
        return Err(format!(
            "{} is not owner-owned at mode 0700",
            path.display()
        ));
    }
    Ok(())
}

/// A fork can inherit another test thread's writable stub descriptor, making its exec fail with ETXTBSY; at commit 1303417c4, library/std/src/sys/process/unix/unix.rs waits for close-on-exec EOF or the error written after `do_exec` before returning from fork-path spawn (lines 104, 138-160).
/// That file delegates the other path to `posix_spawnp` (lines 456-475, 783); Linux glibc's `CLONE_VFORK` suspension until exec or failure is the platform premise, so the lock across stub writes and direct test-side spawns closes the inherited-descriptor window and can end before waiting for the child.
/// For output callers with unconfigured streams, library/std/src/process.rs documents inherited stdio for spawn and noninherited stdin for output (lines 1063, 1095-1096, 1103, 1138-1139), library/std/src/sys/process/mod.rs selects `MakePipe` (lines 54-57), and library/std/src/sys/process/unix/common.rs selects null stdin (lines 358-365).
static STUB_PROCESS_LOCK: Mutex<()> = Mutex::new(());

pub fn write_executable(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

pub fn spawn_serialized(command: &mut Command) -> std::io::Result<Child> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    command.spawn()
}

#[allow(dead_code)]
pub trait SerializedCommand {
    fn spawn_serialized(&mut self) -> std::io::Result<Child>;
    fn output_serialized(&mut self) -> std::io::Result<Output>;
    fn output_serialized_with_stdin(&mut self, stdin: impl Into<Stdio>) -> std::io::Result<Output>;
    fn status_serialized(&mut self) -> std::io::Result<ExitStatus>;
}

impl SerializedCommand for Command {
    fn spawn_serialized(&mut self) -> std::io::Result<Child> {
        spawn_serialized(self)
    }

    fn output_serialized(&mut self) -> std::io::Result<Output> {
        self.output_serialized_with_stdin(Stdio::null())
    }

    fn output_serialized_with_stdin(&mut self, stdin: impl Into<Stdio>) -> std::io::Result<Output> {
        self.stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        spawn_serialized(self)?.wait_with_output()
    }

    fn status_serialized(&mut self) -> std::io::Result<ExitStatus> {
        spawn_serialized(self)?.wait()
    }
}

pub struct TestDir {
    path: PathBuf,
}

impl TestDir {
    #[must_use]
    pub fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "loop-home-subprocess-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create subprocess test directory");
        Self { path }
    }

    #[must_use]
    pub fn new_safe(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "loop-home-subprocess-{}-{sequence}-{label}",
            std::process::id()
        );
        let mut attempts = Vec::new();
        for base in [
            std::env::temp_dir(),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
        ] {
            if !base.is_absolute() {
                attempts.push(format!("{} is not absolute", base.display()));
                continue;
            }
            let path = base.join(&name);
            if let Err(error) = fs::create_dir(&path) {
                attempts.push(format!("{}: {error}", path.display()));
                continue;
            }
            if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o700)) {
                attempts.push(format!("{}: cannot set mode 0700: {error}", path.display()));
                fs::remove_dir(&path).expect("remove rejected safe-path fixture");
                continue;
            }
            match safe_fixture_path(&path) {
                Ok(()) => return Self { path },
                Err(reason) => {
                    attempts.push(format!("{}: {reason}", path.display()));
                    fs::remove_dir(&path).expect("remove rejected safe-path fixture");
                }
            }
        }
        panic!(
            "safe-path fixture prerequisite: no writable temporary base with trusted, link-free ancestors and owner UID/GID: {}",
            attempts.join("; ")
        );
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn prepare(&self) -> (PathBuf, PathBuf) {
        let root = self.path.clone();
        let allocations_dir = root.join(".config/loops");
        fs::create_dir_all(&allocations_dir).expect("allocation directory");
        fs::set_permissions(root.join(".config"), fs::Permissions::from_mode(0o700))
            .expect("config mode");
        fs::set_permissions(&allocations_dir, fs::Permissions::from_mode(0o700))
            .expect("loops mode");
        let allocations = allocations_dir.join("allocations.toml");
        fs::write(
            &allocations,
            "[alpha]\nuids = { base = 40000, count = 4 }\n",
        )
        .expect("allocation ledger");
        fs::set_permissions(allocations, fs::Permissions::from_mode(0o600)).expect("ledger mode");
        fs::write(
            root.join("registry.toml"),
            "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", session = \"SESSION-ID\" }]\n",
        )
        .expect("write registry record");
        let stub = self.path.join("podman-stub");
        write_executable(
            &stub,
            b"#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > \"$ENTER_LOOP_STUB_LOG\"\nif [ \"${3:-}\" = inspect-roots ]; then inspection=${ENTER_LOOP_STUB_INSPECTION_STATUS:-0}; rows='[]'; if [ \"$inspection\" = 3 ]; then rows='[{\"action\":\"create\"},{\"action\":\"create\"},{\"action\":\"correct\"}]'; fi; if [ \"$inspection\" = 4 ]; then rows='[{\"action\":\"refuse\"},{\"action\":\"create\"},{\"action\":\"create\"},{\"action\":\"correct\"}]'; fi; printf 'inspection %s %s %s\\n%s\\n' \"$inspection\" \"${ENTER_LOOP_STUB_WOULD_CREATE:-0}\" \"${ENTER_LOOP_STUB_WOULD_CORRECT:-0}\" \"$rows\" >> \"$7\"; exit \"$inspection\"; fi\nscript=$4\ncase \"$script\" in\n    *'mounts_left='*) printf 'mounts_left=0\\ntmp_left=0\\n'; exit \"${ENTER_LOOP_STUB_CLEANUP_STATUS:-$ENTER_LOOP_STUB_STATUS}\" ;;\nesac\nline=$(printf '%s\\n' \"$script\" | sed -n '3p')\nif [ -z \"$line\" ]; then line=$script; fi\ncase \"$line\" in *' ensure-roots '*) eval \"set -- $line\" ;; *) set -- ignored ignored ;; esac\nif [ \"$2\" = ensure-roots ]; then\n    if [ \"${ENTER_LOOP_STUB_ROWS:-both}\" = none ]; then\n        printf 'wall 42\\n' >> \"$6\"\n    else\n        printf 'created /fixture/new 0700\\ncorrected /fixture/old 0755 0700\\nwall 42\\n' >> \"$6\"\n    fi\n    printf '%s\\n' \"$6\" > \"$ENTER_LOOP_STUB_LOG.report\"\n    stat -c %a \"$6\" > \"$ENTER_LOOP_STUB_LOG.mode\"\nfi\ncase \"$script\" in\n    *'user=%s'*) printf 'user=alpha\\0uid=41001\\0groups=41001\\0home=%s\\0env=USER=alpha\\0' \"$HOME\" ;;\nesac\nexit \"$ENTER_LOOP_STUB_STATUS\"\n",
            0o755,
        )
        .expect("write podman stub");
        (root, stub)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("remove subprocess test directory");
    }
}
