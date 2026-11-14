//! Test-only native stdin/stdout/stderr peer. This is not encryption or an operator artifact.
use std::io::{Read as _, Write as _};

fn main() {
    if let Err(code) = run() {
        std::process::exit(code);
    }
}
fn run() -> Result<(), i32> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 5
        || args[0] != "encrypt"
        || args[1] != "--with-key=host"
        || args[3] != "-"
        || args[4] != "-"
        || std::env::vars_os().next().is_some()
    {
        return Err(90);
    }
    let mode = args[2].strip_prefix("--name=").ok_or(91)?;
    // Enumeration is confined to this synthetic observer, never the production probe.
    let mut extras = std::fs::read_dir("/proc/self/fd")
        .map_err(|_| 92)?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|fd| *fd >= 3)
        .collect::<Vec<_>>();
    extras.sort_unstable();
    // read_dir itself holds the sole descriptor above stderr while enumerating.
    if extras.len() != 1 {
        return Err(93);
    }
    let status = std::fs::read_to_string("/proc/self/status").map_err(|_| 94)?;
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        if status
            .lines()
            .find(|l| l.starts_with(key))
            .is_none_or(|l| l.split_whitespace().nth(1) != Some("0000000000000000"))
        {
            return Err(95);
        }
    }
    if !status.lines().any(|l| l == "NoNewPrivs:\t1") {
        return Err(96);
    }
    if mode == "early" {
        return Ok(());
    }
    if mode == "diagnostic" {
        for _ in 0..8 {
            std::io::stderr().write_all(&[b'X'; 4096]).map_err(|_| 97)?;
        }
        return Ok(());
    }
    if mode == "partial" {
        let mut one = [0];
        nix::unistd::read(std::io::stdin(), &mut one).map_err(|_| 98)?;
        std::io::stdout().write_all(b"QQ==\n").map_err(|_| 99)?;
        return Ok(());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(2 * 1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|_| 100)?;
    if mode == "excess" {
        for _ in 0..16 {
            std::io::stdout()
                .write_all(&[b'A'; 4096])
                .map_err(|_| 101)?;
        }
        return Ok(());
    }
    if mode == "empty" {
        return Ok(());
    }
    let mut encoded = Vec::new();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for part in bytes.chunks(3) {
        let a = part[0];
        let b = part.get(1).copied().unwrap_or(0);
        let c = part.get(2).copied().unwrap_or(0);
        encoded.push(alphabet[usize::from(a >> 2)]);
        encoded.push(alphabet[usize::from(((a & 3) << 4) | (b >> 4))]);
        encoded.push(if part.len() > 1 {
            alphabet[usize::from(((b & 15) << 2) | (c >> 6))]
        } else {
            b'='
        });
        encoded.push(if part.len() > 2 {
            alphabet[usize::from(c & 63)]
        } else {
            b'='
        });
    }
    encoded.push(b'\n');
    std::io::stdout().write_all(&encoded).map_err(|_| 102)?;
    if mode == "fail" {
        return Err(7);
    }
    if mode == "signal" {
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGTERM).map_err(|_| 103)?;
    }
    Ok(())
}
