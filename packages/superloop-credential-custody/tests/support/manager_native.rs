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
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "emit") {
        return stopped_fixture(&args);
    }
    for fd in 3..=2048 {
        if unsafe_fd(fd) {
            return Err("descriptor".into());
        }
    }
    if args.first().is_some_and(|a| a == "--control-client") {
        return control_client(&args);
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
    if args.iter().any(|a| a == "stop") {
        if root.join("manager-require-retained").exists() {
            let retained: serde_json::Value =
                serde_json::from_slice(&fs::read(root.join("evidence/sample/state-07.json"))?)?;
            if retained["phase"] != "generator-retained" || !retained["generator"].is_object() {
                return Err("generator not retained".into());
            }
        }
        fs::write(root.join("manager-stopped"), b"stop\n")?;
        if root.join("manager-unload-after-stop").exists() {
            fs::remove_file(root.join("manager-reply"))?;
        }
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

fn control_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    if args.len() != 2 {
        return Err("control arguments".into());
    }
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    let mut stream = UnixStream::connect(&args[1])?;
    stream.write_all(&bytes)?;
    stream.shutdown(Shutdown::Write)?;
    std::io::stdout().write_all(b"connected\n")?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    std::io::stdout().write_all(&response)?;
    Ok(())
}
