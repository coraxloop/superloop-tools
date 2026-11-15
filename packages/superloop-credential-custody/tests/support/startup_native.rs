//! Native entry controls are separate from the small manager/control peer.
use std::io::Write as _;
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    reason = "the peer includes the exact entry-only closure mechanism, not a second implementation"
)]
#[path = "../../src/launch/startup.rs"]
mod startup;
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(std::env::vars_os().count(), 0);
    let result = match args.first().map(String::as_str) {
        Some("--startup-control") => startup_control(&args),
        Some("--root-control") => root_control(),
        _ => Err("arguments".into()),
    };
    if result.is_err() {
        std::process::exit(71);
    }
}
#[allow(unsafe_code)]
fn unsafe_fd(fd: i32) -> bool {
    // SAFETY: scalar query, never reads inherited bytes.
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
