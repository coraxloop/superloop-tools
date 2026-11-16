use nix::mount::{MsFlags, mount};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

#[allow(unsafe_code)]
pub(super) fn account(name: &str, uid: u32, home: &Path) -> std::io::Result<()> {
    // SAFETY: unshare receives only the fixed mount-namespace flag, no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;
    // Account files live only in this mount namespace. Detach the staging
    // tmpfs after binding them, restoring the original /tmp before the consumer.
    mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        Some("mode=1777,size=1m"),
    )?;
    for (target, row) in [
        (
            "/etc/passwd",
            format!(
                "{name}:x:{uid}:{uid}:{name} superloop:{}:/bin/bash\n",
                home.display()
            ),
        ),
        ("/etc/group", format!("{name}:x:{uid}:\n")),
    ] {
        let mut text = std::fs::read_to_string(target)?;
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&row);
        let source = format!(
            "/tmp/door-{}",
            target.rsplit('/').next().expect("account leaf")
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source)?;
        file.write_all(text.as_bytes())?;
        nix::sys::stat::fchmod(&file, nix::sys::stat::Mode::from_bits_truncate(0o444))?;
        drop(file);
        mount(
            Some(source.as_str()),
            target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;

        std::fs::remove_file(&source)?;
        mount(
            None::<&str>,
            target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )?;
    }
    nix::mount::umount2("/tmp", nix::mount::MntFlags::MNT_DETACH)?;
    Ok(())
}
