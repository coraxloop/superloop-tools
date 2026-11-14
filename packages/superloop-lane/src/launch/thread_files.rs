//! Existence-only evidence for a failed round's retained vendor session.

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use serde_json::{Value, json};

use crate::error::LaneError;
use crate::settings::BoxBackend;

fn refusal(detail: impl std::fmt::Display) -> LaneError {
    LaneError::input("round-thread-files", detail.to_string())
}

fn open(
    directory: &std::fs::File,
    name: &Path,
    flags: OFlag,
) -> Result<Option<std::fs::File>, LaneError> {
    match openat2(
        directory,
        name,
        OpenHow::new()
            .flags(flags | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => Ok(Some(std::fs::File::from(fd))),
        Err(nix::errno::Errno::ENOENT) => Ok(None),
        Err(error) => Err(refusal(error)),
    }
}

pub(super) fn inspect(plan: &crate::plan::Plan, thread: Option<&str>) -> Result<Value, LaneError> {
    let Some(thread) = thread else {
        return Ok(json!({"state":"no-recorded-thread","present":false,
            "vendor_acceptance":"not-checked: existence does not prove vendor acceptance"}));
    };
    let backend = BoxBackend::from_plan(&plan.document)?;
    let home = std::fs::File::from(crate::home::pin_parent(
        &plan.home,
        nix::unistd::Uid::effective().as_raw(),
    )?);
    let roots = match backend {
        BoxBackend::Codex => vec![
            ".codex/sessions".to_owned(),
            ".codex/archived_sessions".to_owned(),
        ],
        BoxBackend::Claude => {
            let words = plan.document["runtime_argv"]
                .as_array()
                .ok_or_else(|| refusal("runtime argv absent"))?;
            let cwd = words
                .windows(2)
                .find(|pair| pair[0] == "--workdir")
                .and_then(|pair| pair[1].as_str())
                .ok_or_else(|| refusal("workdir absent"))?;
            let slug: String = cwd
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect();
            vec![format!(".claude/projects/{slug}")]
        }
    };
    let worker = plan.document["worker_uid"]
        .as_u64()
        .ok_or_else(|| refusal("worker uid absent"))?;
    let mut remaining = 4096;
    let mut present = false;
    for root in &roots {
        if let Some(directory) = open(&home, Path::new(root), OFlag::O_RDONLY | OFlag::O_DIRECTORY)?
        {
            present |= scan(&directory, backend, thread, worker, 0, &mut remaining)?;
        }
    }
    Ok(
        json!({"state":"checked","present":present,"roots":roots,"entry_bound":4096,
        "vendor_acceptance":"not-checked: existence does not prove vendor acceptance"}),
    )
}

fn scan(
    directory: &std::fs::File,
    backend: BoxBackend,
    thread: &str,
    worker: u64,
    depth: usize,
    remaining: &mut usize,
) -> Result<bool, LaneError> {
    if depth > 5 {
        return Err(refusal("session directory depth exceeds 5"));
    }
    if u64::from(directory.metadata().map_err(refusal)?.uid()) != worker {
        return Err(refusal("session directory owner differs from worker"));
    }
    let fd = nix::unistd::dup(directory).map_err(refusal)?;
    let mut names = nix::dir::Dir::from_fd(fd).map_err(refusal)?;
    let mut present = false;
    for entry in names.iter() {
        let entry = entry.map_err(refusal)?;
        let name = entry.file_name().to_str().map_err(refusal)?;
        if matches!(name, "." | "..") {
            continue;
        }
        *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| refusal("session entry bound exceeds 4096"))?;
        let file = open(directory, Path::new(name), OFlag::O_PATH)?
            .ok_or_else(|| refusal("session entry changed during scan"))?;
        let meta = file.metadata().map_err(refusal)?;
        if meta.is_dir() {
            if backend == BoxBackend::Codex {
                let child = open(&file, Path::new("."), OFlag::O_RDONLY | OFlag::O_DIRECTORY)?
                    .ok_or_else(|| refusal("session directory vanished"))?;
                present |= scan(&child, backend, thread, worker, depth + 1, remaining)?;
            }
        } else if meta.is_file() {
            let matches = match backend {
                BoxBackend::Codex => {
                    name.starts_with("rollout-") && name.ends_with(&format!("-{thread}.jsonl"))
                }
                BoxBackend::Claude => name == format!("{thread}.jsonl"),
            };
            if matches && u64::from(meta.uid()) != worker {
                return Err(refusal("session file owner differs from worker"));
            }
            present |= matches;
        } else {
            return Err(refusal(
                "session entry is neither a regular file nor directory",
            ));
        }
    }
    Ok(present)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_plan(home: &Path, backend: &str) -> crate::plan::Plan {
        crate::plan::Plan {
            home: home.to_path_buf(),
            driver_dir: home.join("run"),
            letter: home.join("letter"),
            document: json!({"backend":backend,
                "worker_uid":nix::unistd::Uid::effective().as_raw(),
                "runtime_argv":["podman","--workdir","/home/worker"]}),
        }
    }

    /// Session evidence checks names and custody without reading conversation contents.
    ///
    /// # Panics
    /// Panics if the fixture or existence contract fails.
    /// ´test:unit:failed-round-thread-files-are-existence-only´
    #[test]
    fn failed_round_thread_files_are_existence_only() {
        for (backend, relative) in [
            (
                "codex",
                ".codex/sessions/2026/11/14/rollout-time-thread-1.jsonl",
            ),
            ("claude", ".claude/projects/-home-worker/thread-1.jsonl"),
        ] {
            let root = tempfile::tempdir().expect("fixture");
            let home = root.path();
            let plan = fixture_plan(home, backend);
            assert_eq!(
                inspect(&plan, Some("thread-1")).expect("absent")["present"],
                false
            );
            let leaf = home.join(relative);
            std::fs::create_dir_all(leaf.parent().expect("parent")).expect("parents");
            std::fs::write(&leaf, b"not conversation JSON").expect("synthetic bytes");
            let found = inspect(&plan, Some("thread-1")).expect("exists");
            assert_eq!(found["present"], true);
            assert!(
                found["vendor_acceptance"]
                    .as_str()
                    .expect("limit")
                    .contains("does not prove")
            );
            assert_eq!(
                inspect(&plan, Some("other")).expect("different")["present"],
                false
            );
            assert_eq!(
                inspect(&plan, None).expect("none")["state"],
                "no-recorded-thread"
            );
            std::fs::remove_file(&leaf).expect("remove fixture");
            std::os::unix::fs::symlink(home.join("outside"), &leaf).expect("link");
            assert_eq!(
                inspect(&plan, Some("thread-1")).expect_err("no links").kind,
                "round-thread-files"
            );
        }
    }

    /// A scan cannot return a false absence after exhausting its entry allowance.
    ///
    /// # Panics
    /// Panics if the bounded scan does not refuse.
    /// ´test:unit:failed-round-thread-files-refuse-an-exhausted-bound´
    #[test]
    fn failed_round_thread_files_refuse_an_exhausted_bound() {
        let root = tempfile::tempdir().expect("fixture");
        std::fs::write(root.path().join("one"), b"").expect("entry");
        let file = std::fs::File::open(root.path()).expect("directory");
        let error = scan(
            &file,
            BoxBackend::Codex,
            "thread",
            u64::from(nix::unistd::Uid::effective().as_raw()),
            0,
            &mut 0,
        )
        .expect_err("bound");
        assert!(error.detail.contains("4096"));
    }
}
