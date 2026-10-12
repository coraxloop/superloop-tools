//! Owner process evidence for a home move, independent of retirement's absence rules.

use super::Result;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

fn gone(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

pub(super) fn scan(root: &Path, paths: &[String]) -> Result<usize> {
    let entries = fs::read_dir(root).map_err(|_| "claude-home-driver-unreadable")?;
    let words = paths
        .iter()
        .map(|path| format!("CLAUDE_CONFIG_DIR={path}").into_bytes())
        .collect::<Vec<_>>();
    let mut pids = Vec::new();
    let mut unreadable = false;
    let mut environ_unreadable = 0;
    for entry in entries {
        let entry = entry.map_err(|_| "claude-home-driver-unreadable")?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) if gone(&error) => continue,
            Err(_) => {
                unreadable = true;
                continue;
            }
        };
        if metadata.uid() != super::owner_uid() {
            continue;
        }
        let mut matched = false;
        for name in ["cmdline", "environ"] {
            match fs::read(entry.path().join(name)) {
                Ok(bytes) => {
                    matched |= bytes
                        .split(|byte| *byte == 0)
                        .any(|word| words.iter().any(|candidate| candidate == word));
                }
                Err(error) if gone(&error) => {}
                Err(_) if name == "environ" => environ_unreadable += 1,
                Err(_) => unreadable = true,
            }
        }
        if matched {
            pids.push(pid);
        }
    }
    if !pids.is_empty() {
        pids.sort_unstable();
        return Err(format!(
            "claude-home-driver-live: {}",
            serde_json::json!(pids)
        ));
    }
    if unreadable {
        return Err("claude-home-driver-unreadable".into());
    }
    Ok(environ_unreadable)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Panics only if the synthetic process table or scanner contract fails.
    /// ´test:unit:claude-move-scan-requires-exact-home-and-readable-environment´
    #[test]
    fn claude_move_scan_requires_exact_home_and_readable_environment() {
        let root = tempfile::tempdir().expect("process table");
        let process = root.path().join("123");
        fs::create_dir(&process).expect("process");
        fs::write(
            process.join("cmdline"),
            b"claude\0CLAUDE_CONFIG_DIR=/owner/.claude-alpha-extra\0",
        )
        .expect("cmdline");
        fs::write(process.join("environ"), b"HOME=/owner\0").expect("environment");
        let paths = vec!["/owner/.claude-alpha".to_owned()];
        assert_eq!(scan(root.path(), &paths).expect("readable"), 0);
        fs::write(
            process.join("cmdline"),
            b"env\0CLAUDE_CONFIG_DIR=/owner/.claude-alpha\0claude\0",
        )
        .expect("cmdline");
        assert_eq!(
            scan(root.path(), &paths).expect_err("live"),
            "claude-home-driver-live: [123]"
        );
        fs::write(process.join("cmdline"), b"claude\0").expect("cmdline");
        fs::write(
            process.join("environ"),
            b"CLAUDE_CONFIG_DIR=/owner/.claude-alpha\0",
        )
        .expect("environment");
        assert_eq!(
            scan(root.path(), &paths).expect_err("live"),
            "claude-home-driver-live: [123]"
        );
        fs::remove_file(process.join("environ")).expect("remove environment");
        fs::create_dir(process.join("environ")).expect("unreadable environment");
        assert_eq!(scan(root.path(), &paths).expect("command words only"), 1);
        fs::write(
            process.join("cmdline"),
            b"env\0CLAUDE_CONFIG_DIR=/owner/.claude-alpha\0claude\0",
        )
        .expect("cmdline");
        assert_eq!(
            scan(root.path(), &paths).expect_err("live without environment"),
            "claude-home-driver-live: [123]"
        );
        fs::remove_file(process.join("cmdline")).expect("remove command line");
        fs::create_dir(process.join("cmdline")).expect("unreadable command line");
        assert_eq!(
            scan(root.path(), &paths).expect_err("unreadable"),
            "claude-home-driver-unreadable"
        );
    }
}
