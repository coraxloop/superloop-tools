use crate::Result;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;

pub struct Entry {
    pub path: PathBuf,
    pub digest: String,
    pub size: u64,
}
pub struct Manifest {
    pub headers: Vec<u8>,
    pub entries: Vec<Entry>,
    pub digest: String,
    pub bytes: u64,
}

pub fn parse(bytes: &[u8]) -> Result<Manifest> {
    let mut result = Manifest {
        headers: Vec::new(),
        entries: Vec::new(),
        digest: hex(&Sha256::digest(bytes)),
        bytes: 0,
    };
    let mut paths = BTreeSet::new();
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        if content.is_empty() {
            return Err("malformed-manifest: empty line or NUL".into());
        }
        if result.entries.is_empty() && header(content) {
            result.headers.extend_from_slice(line);
            if !line.ends_with(b"\n") {
                result.headers.push(b'\n');
            }
            continue;
        }
        let mut fields = content.splitn(3, |b| *b == b' ');
        let hash = fields.next().ok_or("malformed-manifest")?;
        let size = fields.next().ok_or("malformed-manifest")?;
        let path = fields.next().ok_or("malformed-manifest")?;
        if hash.len() != 64
            || !hash
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            || path.contains(&0)
            || size.is_empty()
            || !size.iter().all(u8::is_ascii_digit)
            || !valid_path(path)
        {
            return Err("malformed-manifest: digest, size or relative path".into());
        }
        let path = PathBuf::from(OsString::from_vec(path.to_vec()));
        if !paths.insert(path.clone()) {
            return Err("malformed-manifest: duplicate path".into());
        }
        let size: u64 = std::str::from_utf8(size)?.parse()?;
        result.bytes = result
            .bytes
            .checked_add(size)
            .ok_or("manifest-size-overflow")?;
        result.entries.push(Entry {
            path,
            size,
            digest: std::str::from_utf8(hash)?.to_owned(),
        });
    }
    Ok(result)
}
fn header(line: &[u8]) -> bool {
    line.iter().position(|b| *b == b'=').is_some_and(|n| {
        n > 0
            && line[..n]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(b))
    })
}
fn valid_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path
            .split(|b| *b == b'/')
            .all(|p| !p.is_empty() && p != b"." && p != b"..")
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ignored = write!(result, "{byte:02x}");
    }
    result
}
