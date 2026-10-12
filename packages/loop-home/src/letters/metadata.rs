use super::record::{LetterRecord, malformed, parse_name};
use crate::LoopError;

/// Validated metadata shared by the letters producer and its hook reader.
pub struct LetterMetadata {
    pub name: String,
    pub sender: String,
    pub bytes: u64,
    pub posted_ns: u64,
    pub subject: String,
    pub unread: bool,
}

impl LetterMetadata {
    fn line(&self) -> Result<String, LoopError> {
        let subject = serde_json::to_string(&self.subject).map_err(super::io_error)?;
        let directory = if self.unread { "new" } else { "cur" };
        Ok(format!(
            "{directory}/{} sender={} bytes={} posted_ns={} subject={subject}",
            self.name, self.sender, self.bytes, self.posted_ns
        ))
    }
}

/// Produce a listing line from the canonical letter record, without exposing its body.
///
/// # Errors
/// Refuses a malformed record, directory or name, or a name that disagrees with the record.
pub fn letter_metadata(directory: &str, name: &str, bytes: &[u8]) -> Result<String, LoopError> {
    let record = LetterRecord::decode(bytes)?;
    let (sender, instant) = parse_name(name)?;
    if sender != record.sender || instant != record.posted_ns || !matches!(directory, "new" | "cur")
    {
        return Err(malformed());
    }
    LetterMetadata {
        name: name.to_owned(),
        sender: record.sender,
        bytes: u64::try_from(bytes.len()).map_err(super::io_error)?,
        posted_ns: instant,
        subject: record.subject,
        unread: directory == "new",
    }
    .line()
}

/// Read exactly the current five-field listing shape, including a canonical JSON subject.
///
/// # Errors
/// Refuses missing, extra, malformed or noncanonical fields, including the old four-field shape.
pub fn parse_letter_metadata(line: &str) -> Result<LetterMetadata, LoopError> {
    let fields = line.splitn(5, ' ').collect::<Vec<_>>();
    let [path, sender, bytes, instant, subject] = fields.as_slice() else {
        return Err(malformed());
    };
    let (directory, name) = path.split_once('/').unwrap_or(("new", path));
    let (name_sender, name_instant) = parse_name(name)?;
    let sender = sender.strip_prefix("sender=").ok_or_else(malformed)?;
    let bytes = bytes
        .strip_prefix("bytes=")
        .ok_or_else(malformed)?
        .parse()
        .map_err(|_| malformed())?;
    let posted_ns = instant
        .strip_prefix("posted_ns=")
        .ok_or_else(malformed)?
        .parse()
        .map_err(|_| malformed())?;
    let subject: String =
        serde_json::from_str(subject.strip_prefix("subject=").ok_or_else(malformed)?)
            .map_err(|_| malformed())?;
    if !matches!(directory, "new" | "cur")
        || sender != name_sender
        || posted_ns != name_instant
        || subject.len() > 1024
        || subject.chars().any(char::is_control)
    {
        return Err(malformed());
    }
    let metadata = LetterMetadata {
        name: name.to_owned(),
        sender: sender.to_owned(),
        bytes,
        posted_ns,
        subject,
        unread: directory == "new",
    };
    let canonical = metadata.line()?;
    let expected = if path.contains('/') {
        canonical.as_str()
    } else {
        canonical.strip_prefix("new/").ok_or_else(malformed)?
    };
    if expected != line {
        return Err(malformed());
    }
    Ok(metadata)
}
