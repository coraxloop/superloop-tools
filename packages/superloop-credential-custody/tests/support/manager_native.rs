//! Test-only manager CLI peer: records vectors and supplies synthetic metadata.
use std::fs;
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    reason = "the peer includes the exact entry-only closure mechanism, not a second implementation"
)]
#[path = "../../src/launch/startup.rs"]
mod startup;
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
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "--startup-control") {
        return startup_control(&args);
    }
    if args.first().is_some_and(|a| a == "--root-control") {
        return root_control();
    }
    if args.first().is_some_and(|a| a == "emit") {
        return stopped_fixture(&args);
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
    if args.iter().any(|a| a == "--no-block") && !args.iter().any(|a| a == "--quiet") {
        let unit = args
            .iter()
            .find_map(|a| a.strip_prefix("--unit="))
            .ok_or("unit")?;
        writeln!(
            std::io::stderr(),
            "Running as unit: {unit}; invocation ID: 1234567890abcdef1234567890abcdef"
        )?;
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

#[allow(unsafe_code)]
fn startup_control(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let fd = args.get(1).ok_or("fd")?.parse::<i32>()?;
    if fd < 9 || !unsafe_fd(fd) {
        return Err("ambient missing".into());
    }
    // SAFETY: this native peer is single-threaded and owns no nonstandard
    // descriptors; the selected fd is an inherited raw capability only.
    unsafe {
        startup::close_inherited().map_err(std::io::Error::other)?;
    }
    if unsafe_fd(fd) {
        return Err("ambient retained".into());
    }
    std::io::stdout().write_all(b"resident-descriptors-closed\n")?;
    Ok(())
}
#[allow(unsafe_code)]
fn stopped_fixture(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::FromRawFd as _;
    if args.len() != 3 || args[1] != "--case-record" {
        return Err("fixture arguments".into());
    }
    for fd in [3, 4] {
        if !unsafe_fd(fd) {
            return Err("fixture descriptors".into());
        }
    }
    for fd in 5..=2048 {
        if unsafe_fd(fd) {
            return Err("fixture extra descriptor".into());
        }
    }
    nix::sys::signal::raise(nix::sys::signal::Signal::SIGSTOP)?;
    // SAFETY: this private native peer alone owns the two validated slots.
    for fd in [3, 4] {
        let mut writer = unsafe { fs::File::from_raw_fd(fd) };
        writer.write_all(b"synthetic")?;
    }
    Ok(())
}

#[allow(unsafe_code)]
fn root_control() -> Result<(), Box<dyn std::error::Error>> {
    if nix::unistd::geteuid().as_raw() == 0 {
        return Err("ordinary control required".into());
    }
    // SAFETY: this fresh native peer is single-threaded with no owned fd above 2.
    if unsafe { startup::RootStartup::initialize() }.err() != Some("keeper-root-required") {
        return Err("root guard".into());
    }
    std::io::stdout().write_all(b"root-required\n")?;
    Ok(())
}
