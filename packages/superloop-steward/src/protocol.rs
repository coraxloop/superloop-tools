use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;

#[derive(Clone, Debug)]
pub struct Row {
    pub path: String,
    pub size: u64,
    pub identity: String,
    pub stamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub offset: u64,
    pub high: u64,
    pub observed: u64,
    pub stamp: String,
    pub tail_start: u64,
    pub tail_hash: String,
}

pub type Positions = BTreeMap<(String, String), Position>;

fn uint(text: &str) -> io::Result<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::other("invalid protocol integer"));
    }
    text.parse()
        .map_err(|_| io::Error::other("protocol integer overflow"))
}

fn pair(text: &str) -> io::Result<()> {
    let (a, b) = text
        .split_once(':')
        .ok_or_else(|| io::Error::other("invalid protocol pair"))?;
    uint(a)?;
    uint(b)?;
    Ok(())
}

fn path(text: &str) -> io::Result<()> {
    if text.is_empty()
        || text.chars().any(char::is_control)
        || text
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(io::Error::other("invalid relative transcript path"));
    }
    Ok(())
}

pub fn list(bytes: &[u8]) -> io::Result<Vec<Row>> {
    let text = std::str::from_utf8(bytes).map_err(|_| io::Error::other("invalid list encoding"))?;
    let mut rows = BTreeMap::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split('\t').collect();
        let [relative, size, identity, stamp] = fields.as_slice() else {
            return Err(io::Error::other("invalid list row"));
        };
        path(relative)?;
        pair(identity)?;
        pair(stamp)?;
        let row = Row {
            path: (*relative).to_owned(),
            size: uint(size)?,
            identity: (*identity).to_owned(),
            stamp: (*stamp).to_owned(),
        };
        if rows.insert(row.path.clone(), row).is_some() {
            return Err(io::Error::other("duplicate list path"));
        }
    }
    Ok(rows.into_values().collect())
}

pub fn load(bytes: &[u8]) -> io::Result<Positions> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| io::Error::other("invalid cursor encoding"))?;
    let mut lines = text.lines();
    if lines.next() != Some("V1\tcanary=1") {
        return Err(io::Error::other("invalid cursor header"));
    }
    let mut positions = Positions::new();
    for line in lines {
        let fields: Vec<_> = line.split('\t').collect();
        let [
            "F",
            relative,
            identity,
            offset,
            high,
            observed,
            stamp,
            tail_start,
            tail_hash,
        ] = fields.as_slice()
        else {
            return Err(io::Error::other("invalid cursor row"));
        };
        path(relative)?;
        pair(identity)?;
        pair(stamp)?;
        let position = Position {
            offset: uint(offset)?,
            high: uint(high)?,
            observed: uint(observed)?,
            stamp: (*stamp).to_owned(),
            tail_start: uint(tail_start)?,
            tail_hash: (*tail_hash).to_owned(),
        };
        if position.offset > position.high
            || position.tail_start > position.offset
            || (position.offset == 0 && position.tail_hash != "-")
            || (position.offset > 0
                && (position.tail_hash.len() != 64
                    || !position
                        .tail_hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))))
        {
            return Err(io::Error::other("invalid cursor metadata"));
        }
        if positions
            .insert(((*relative).to_owned(), (*identity).to_owned()), position)
            .is_some()
        {
            return Err(io::Error::other("duplicate cursor key"));
        }
    }
    Ok(positions)
}

pub fn encode(positions: &Positions) -> io::Result<Vec<u8>> {
    let mut text = String::from("V1\tcanary=1\n");
    for ((path, identity), p) in positions {
        writeln!(
            text,
            "F\t{path}\t{identity}\t{}\t{}\t{}\t{}\t{}\t{}",
            p.offset, p.high, p.observed, p.stamp, p.tail_start, p.tail_hash
        )
        .map_err(io::Error::other)?;
    }
    Ok(text.into_bytes())
}

pub fn digest(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _written = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub fn noise(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let protected = [
        "\"type\":\"user\"",
        "\"type\":\"assistant\"",
        "prompt",
        "decision",
        "command",
        "sudo",
        "case_id",
        "case-id",
        "refusal",
        "refused",
        "error",
        "warning",
    ];
    text.contains("\"type\":\"file-history-snapshot\"")
        && !protected.iter().any(|word| text.contains(word))
}
