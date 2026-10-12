use std::fmt::Write as _;

use crate::{LoopError, validate_name};

pub(super) const MAX_BODY: usize = 65_536;
pub(super) const MAX_HEADER: usize = 4096;

/// One versioned header followed by exactly the declared number of body bytes.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct LetterRecord {
    pub sender: String,
    pub receiver: String,
    pub subject: String,
    pub posted_ns: u64,
    pub body: Vec<u8>,
}

pub(super) fn malformed() -> LoopError {
    LoopError::refusal("letters malformed letter")
}

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut result = String::new();
    for byte in bytes {
        let _written = write!(&mut result, "{byte:02x}");
    }
    result
}

fn unhex(value: &str) -> Result<Vec<u8>, LoopError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok(digit(pair[0]) * 16 + digit(pair[1]))
        })
        .collect()
}

impl LetterRecord {
    pub fn encode(&self) -> Result<Vec<u8>, LoopError> {
        validate_name(&self.sender).map_err(|_| malformed())?;
        validate_name(&self.receiver).map_err(|_| malformed())?;
        if self.body.len() > MAX_BODY {
            return Err(LoopError::refusal("letters oversized body"));
        }
        if self.subject.len() > 1024
            || self.subject.chars().any(char::is_control)
            || self.posted_ns == 0
            || self.sender == self.receiver
        {
            return Err(malformed());
        }
        let header = format!(
            "LOOP-LETTER 1\nsender={}\nreceiver={}\nposted_ns={}\nsubject_hex={}\nbody_bytes={}\n\n",
            self.sender,
            self.receiver,
            self.posted_ns,
            hex(self.subject.as_bytes()),
            self.body.len()
        );
        if header.len() > MAX_HEADER {
            return Err(malformed());
        }
        let mut bytes = header.into_bytes();
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LoopError> {
        let end = bytes
            .windows(2)
            .position(|pair| pair == b"\n\n")
            .ok_or_else(malformed)?
            + 2;
        if end > MAX_HEADER {
            return Err(malformed());
        }
        let header = std::str::from_utf8(&bytes[..end - 2]).map_err(|_| malformed())?;
        let lines = header.lines().collect::<Vec<_>>();
        let ["LOOP-LETTER 1", sender, receiver, posted, subject, length] = lines.as_slice() else {
            return Err(malformed());
        };
        let field = |line: &str, prefix: &str| {
            line.strip_prefix(prefix)
                .map(str::to_owned)
                .ok_or_else(malformed)
        };
        let record = Self {
            sender: field(sender, "sender=")?,
            receiver: field(receiver, "receiver=")?,
            posted_ns: field(posted, "posted_ns=")?
                .parse()
                .map_err(|_| malformed())?,
            subject: String::from_utf8(unhex(&field(subject, "subject_hex=")?)?)
                .map_err(|_| malformed())?,
            body: bytes[end..].to_vec(),
        };
        let size: usize = field(length, "body_bytes=")?
            .parse()
            .map_err(|_| malformed())?;
        if record.body.len() != size || record.encode()? != bytes {
            return Err(malformed());
        }
        Ok(record)
    }
}

pub(super) fn parse_name(name: &str) -> Result<(&str, u64), LoopError> {
    let mut parts = name.rsplitn(3, '.');
    let suffix = parts.next().ok_or_else(malformed)?;
    let instant = parts.next().ok_or_else(malformed)?;
    let sender = parts.next().ok_or_else(malformed)?;
    validate_name(sender).map_err(|_| malformed())?;
    if name.len() > 255
        || suffix.len() != 32
        || unhex(suffix).is_err()
        || instant.len() != 20
        || !instant.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(malformed());
    }
    let instant = instant.parse::<u64>().map_err(|_| malformed())?;
    if instant == 0 {
        return Err(malformed());
    }
    Ok((sender, instant))
}
