//! Test-only manager CLI peer: records vectors and supplies synthetic metadata.
use std::fs;
use std::io::{Read as _, Write as _};
fn main() {
    if run().is_err() {
        std::process::exit(71);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let image = std::env::current_exe()?;
    let root = image.parent().ok_or("parent")?;
    if std::env::vars_os().next().is_some() {
        return Err("environment".into());
    }
    for fd in 3..=2048 {
        if unsafe_fd(fd) {
            return Err("descriptor".into());
        }
    }
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    if !input.is_empty() {
        return Err("input".into());
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    fs::write(root.join("manager-argv.json"), serde_json::to_vec(&args)?)?;
    if args
        .iter()
        .any(|a| a == "--version" || a == "--property=Version")
    {
        let bytes = fs::read(root.join("manager-version")).unwrap_or_else(|_| b"257\n".to_vec());
        std::io::stdout().write_all(&bytes)?;
        return Ok(());
    }
    if args.iter().any(|a| a == "show") {
        std::io::stdout().write_all(&fs::read(root.join("manager-reply"))?)?;
    }
    for (operation, name) in [
        ("--no-block", "manager-start-output"),
        ("stop", "manager-stop-output"),
    ] {
        if args.iter().any(|a| a == operation) && root.join(name).exists() {
            std::io::stdout().write_all(&fs::read(root.join(name))?)?;
        }
    }
    Ok(())
}
#[allow(unsafe_code)]
fn unsafe_fd(fd: i32) -> bool {
    // SAFETY: scalar metadata query; the test peer never reads inherited bytes.
    unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) >= 0 }
}
