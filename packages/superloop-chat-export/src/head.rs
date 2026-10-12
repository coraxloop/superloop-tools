//! The first pass's view of one transcript line: the few fields that place a
//! record in the tree and classify it, with everything else skipped unread.

use std::borrow::Cow;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, SeqAccess, Visitor};

/// A record's `uuid`: the sixteen bytes of its canonical 8-4-4-4-12
/// hexadecimal text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordId([u8; 16]);

impl RecordId {
    /// Parses the canonical hyphenated form in either case; any other text is
    /// not a record id.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&at| bytes[at] != b'-') {
            return None;
        }
        let mut digits = bytes
            .iter()
            .enumerate()
            .filter(|(at, _)| ![8, 13, 18, 23].contains(at))
            .map(|(_, &byte)| hex_value(byte));
        let mut id = [0; 16];
        for byte in &mut id {
            let high = digits.next()??;
            let low = digits.next()??;
            *byte = (high << 4) | low;
        }
        Some(Self(id))
    }

    /// The sixteen bytes of the id.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (at, byte) in self.0.iter().enumerate() {
            if matches!(at, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for RecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// The fields of one transcript line the first pass reads.
///
/// Unknown fields are skipped and unknown record, block and attachment kinds
/// are kept as text, so a newer harness's lines still load; a line whose known
/// fields carry the wrong JSON type does not parse and is counted as malformed.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RawHead<'a> {
    #[serde(rename = "type", borrow)]
    pub record_type: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub subtype: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub uuid: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub parent_uuid: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub logical_parent_uuid: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub timestamp: Option<Cow<'a, str>>,
    pub is_sidechain: Option<bool>,
    pub is_meta: Option<bool>,
    pub is_compact_summary: Option<bool>,
    #[serde(borrow)]
    pub origin: Option<OriginHead<'a>>,
    #[serde(borrow)]
    pub message: Option<MessageHead<'a>>,
    #[serde(rename = "sourceToolAssistantUUID", borrow)]
    pub source_tool_assistant_uuid: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub attachment: Option<AttachmentHead<'a>>,
    #[serde(borrow)]
    pub compact_metadata: Option<CompactHead<'a>>,
    #[serde(borrow)]
    pub custom_title: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub ai_title: Option<Cow<'a, str>>,
}

/// Who a message came from, when the harness records it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct OriginHead<'a> {
    #[serde(borrow)]
    pub kind: Option<Cow<'a, str>>,
}

/// An attachment's kind and origin.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AttachmentHead<'a> {
    #[serde(rename = "type", borrow)]
    pub attachment_type: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub origin: Option<OriginHead<'a>>,
}

/// A compaction boundary's metadata: what started it, its token counts, and
/// the preserved tail that can stand in for an absent logical parent.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CompactHead<'a> {
    #[serde(borrow)]
    pub trigger: Option<Cow<'a, str>>,
    pub pre_tokens: Option<serde_json::Number>,
    pub post_tokens: Option<serde_json::Number>,
    pub duration_ms: Option<serde_json::Number>,
    #[serde(borrow)]
    pub preserved_segment: Option<PreservedHead<'a>>,
}

/// The preserved tail of the chain a compaction kept.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PreservedHead<'a> {
    #[serde(borrow)]
    pub tail_uuid: Option<Cow<'a, str>>,
}

/// What the first pass keeps of `message`: the API message it belongs to and
/// the shape of its content.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MessageHead<'a> {
    #[serde(borrow)]
    pub id: Option<Cow<'a, str>>,
    pub content: ContentHead,
}

/// How a message's text opens.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TextShape {
    /// No text block.
    #[default]
    Absent,
    /// Text that is empty or only whitespace.
    Blank,
    /// Text that opens with a tag of the slash-command form.
    CommandTag,
    /// Text that opens with the tag of one of the harness's own forms.
    HarnessTag,
    /// Anything else, a tag of any other name included: words someone wrote.
    Plain,
}

/// The tags a slash command is written in: its name, its message and its
/// arguments.
pub const COMMAND_TAGS: [&str; 3] = ["command-name", "command-message", "command-args"];

/// The harness's own forms of a user record, with the label a page gives each.
///
/// A form is named by the tag its text opens with: a local command's output
/// and caveat, a shell command's output, a reminder and a task notification.
pub const HARNESS_FORMS: [(&str, &str); 7] = [
    ("local-command-stdout", "command output"),
    ("local-command-stderr", "command error output"),
    ("local-command-caveat", "command caveat"),
    ("bash-stdout", "shell output"),
    ("bash-stderr", "shell error output"),
    ("system-reminder", "system reminder"),
    ("task-notification", "task notification"),
];

/// The name of the tag `text` opens with, when it opens with a lower-case tag.
#[must_use]
pub fn opening_tag(text: &str) -> Option<&str> {
    let (name, _) = text.trim_start().strip_prefix('<')?.split_once('>')?;
    let lower = name.starts_with(|character: char| character.is_ascii_lowercase());
    let named = name.chars().all(|character| {
        character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
    });
    (lower && named).then_some(name)
}

/// The label of the harness form whose tag `text` opens with, if any.
#[must_use]
pub fn harness_form(text: &str) -> Option<&'static str> {
    let tag = opening_tag(text)?;
    HARNESS_FORMS
        .iter()
        .find(|(name, _)| *name == tag)
        .map(|(_, label)| *label)
}

/// The block kinds a message carries, the shape of its first text, and the
/// ids of the tool calls it makes and the calls its results answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentHead {
    pub text: TextShape,
    pub tool_use: bool,
    pub tool_result: bool,
    pub thinking: bool,
    /// The id each tool-use block carries, in the order of the blocks, none
    /// for a block that carries none; every block is a call.
    pub calls: Vec<Option<String>>,
    /// The call id each result block names, in the order of the blocks, none
    /// for a block that names no call.
    pub results: Vec<Option<String>>,
}

/// How `text` opens: a tag is the harness's only by its name, so an owner's
/// message that opens with a tag of any other name is the owner's.
fn text_shape(text: &str) -> TextShape {
    if text.trim().is_empty() {
        return TextShape::Blank;
    }
    match opening_tag(text) {
        Some(tag) if COMMAND_TAGS.contains(&tag) => TextShape::CommandTag,
        Some(_) if harness_form(text).is_some() => TextShape::HarnessTag,
        _ => TextShape::Plain,
    }
}

#[derive(Deserialize)]
struct BlockHead<'a> {
    #[serde(rename = "type", borrow, default)]
    block_type: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    text: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    id: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    tool_use_id: Option<Cow<'a, str>>,
}

impl<'de> Deserialize<'de> for ContentHead {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ContentVisitor)
    }
}

struct ContentVisitor;

impl<'de> Visitor<'de> for ContentVisitor {
    type Value = ContentHead;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("message content as text or a list of blocks")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<ContentHead, E> {
        Ok(ContentHead {
            text: text_shape(text),
            ..ContentHead::default()
        })
    }

    fn visit_unit<E: de::Error>(self) -> Result<ContentHead, E> {
        Ok(ContentHead::default())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut blocks: A) -> Result<ContentHead, A::Error> {
        let mut content = ContentHead::default();
        while let Some(block) = blocks.next_element::<BlockOrOther<'de>>()? {
            let BlockOrOther::Block(block) = block else {
                continue;
            };
            match block.block_type.as_deref() {
                Some("text") if content.text == TextShape::Absent => {
                    content.text = text_shape(block.text.as_deref().unwrap_or_default());
                }
                Some("tool_use") => {
                    content.tool_use = true;
                    content.calls.push(block.id.map(Cow::into_owned));
                }
                Some("tool_result") => {
                    content.tool_result = true;
                    content.results.push(block.tool_use_id.map(Cow::into_owned));
                }
                Some("thinking" | "redacted_thinking") => content.thinking = true,
                _ => {}
            }
        }
        Ok(content)
    }
}

/// A content list element: a block object, or anything else skipped.
enum BlockOrOther<'a> {
    Block(BlockHead<'a>),
    Other,
}

impl<'de> Deserialize<'de> for BlockOrOther<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(BlockOrOtherVisitor)
    }
}

struct BlockOrOtherVisitor;

impl<'de> Visitor<'de> for BlockOrOtherVisitor {
    type Value = BlockOrOther<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a content block")
    }

    fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        BlockHead::deserialize(de::value::MapAccessDeserializer::new(map)).map(BlockOrOther::Block)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Self::Value, A::Error> {
        while items.next_element::<IgnoredAny>()?.is_some() {}
        Ok(BlockOrOther::Other)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(BlockOrOther::Other)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(BlockOrOther::Other)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(BlockOrOther::Other)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(BlockOrOther::Other)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(BlockOrOther::Other)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(BlockOrOther::Other)
    }
}

/// What a record is, as far as placing and paging it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Words the owner typed as a prompt.
    Prompt,
    /// A message the owner typed while a turn ran, attached as a queued command.
    QueuedPrompt,
    /// A slash command the owner typed.
    Command,
    /// Any other user record: meta text, harness tags and task notifications.
    UserNote,
    /// A message from another session, sent directly or queued.
    Peer,
    /// A tool's result.
    ToolResult,
    /// The summary a compaction writes.
    CompactSummary,
    /// Assistant text.
    Response,
    /// Assistant thinking without text.
    Thinking,
    /// A tool call without text.
    ToolUse,
    /// A compaction boundary.
    Boundary,
    /// Any other system record.
    SystemNote,
    /// Any other attachment.
    Attachment,
    /// A record type this version does not know.
    Other,
}

impl Kind {
    /// Whether the record opens a turn: the owner's typed prompt or a message
    /// the owner queued while a turn ran. A slash command is the owner's too,
    /// but it acts within the turn it is typed in.
    #[must_use]
    pub const fn opens_turn(self) -> bool {
        matches!(self, Self::Prompt | Self::QueuedPrompt)
    }
}

fn origin_kind<'b>(origin: Option<&'b OriginHead<'_>>) -> Option<&'b str> {
    origin.and_then(|origin| origin.kind.as_deref())
}

impl RawHead<'_> {
    /// Classifies the record from its type, flags, origin and content shape.
    #[must_use]
    pub fn kind(&self) -> Kind {
        let empty = ContentHead::default();
        let content = self
            .message
            .as_ref()
            .map_or(&empty, |message| &message.content);
        let origin = origin_kind(self.origin.as_ref());
        match self.record_type.as_deref() {
            Some("user") => {
                if content.tool_result {
                    Kind::ToolResult
                } else if self.is_compact_summary == Some(true) {
                    Kind::CompactSummary
                } else if origin == Some("peer") {
                    Kind::Peer
                } else if self.is_meta == Some(true) || origin.is_some_and(|kind| kind != "human") {
                    Kind::UserNote
                } else {
                    match content.text {
                        TextShape::Plain => Kind::Prompt,
                        TextShape::CommandTag => Kind::Command,
                        TextShape::Absent | TextShape::Blank | TextShape::HarnessTag => {
                            Kind::UserNote
                        }
                    }
                }
            }
            Some("assistant") => {
                if matches!(content.text, TextShape::Absent | TextShape::Blank) {
                    if content.tool_use {
                        Kind::ToolUse
                    } else if content.thinking {
                        Kind::Thinking
                    } else {
                        Kind::Response
                    }
                } else {
                    Kind::Response
                }
            }
            Some("system") if self.subtype.as_deref() == Some("compact_boundary") => Kind::Boundary,
            Some("system") => Kind::SystemNote,
            Some("attachment") => match &self.attachment {
                Some(attachment)
                    if attachment.attachment_type.as_deref() == Some("queued_command") =>
                {
                    match origin_kind(attachment.origin.as_ref()) {
                        Some("human") => Kind::QueuedPrompt,
                        Some("peer") => Kind::Peer,
                        _ => Kind::Attachment,
                    }
                }
                _ => Kind::Attachment,
            },
            _ => Kind::Other,
        }
    }
}

/// What a compaction boundary records about the compaction: what started it,
/// the tokens before and after, and how long it took.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Compaction {
    pub trigger: Option<String>,
    pub pre_tokens: Option<u64>,
    pub post_tokens: Option<u64>,
    pub duration_ms: Option<u64>,
}

impl RawHead<'_> {
    /// The compaction a boundary records; `None` for any other record.
    #[must_use]
    pub fn compaction(&self) -> Option<Compaction> {
        if self.record_type.as_deref() != Some("system")
            || self.subtype.as_deref() != Some("compact_boundary")
        {
            return None;
        }
        let Some(metadata) = self.compact_metadata.as_ref() else {
            return Some(Compaction::default());
        };
        let count =
            |number: Option<&serde_json::Number>| number.and_then(serde_json::Number::as_u64);
        Some(Compaction {
            trigger: metadata.trigger.as_deref().map(str::to_owned),
            pre_tokens: count(metadata.pre_tokens.as_ref()),
            post_tokens: count(metadata.post_tokens.as_ref()),
            duration_ms: count(metadata.duration_ms.as_ref()),
        })
    }
}

/// The UTC time of day of an instant in milliseconds since the Unix epoch, as
/// `HH:MM:SS UTC`.
#[must_use]
pub fn format_clock(millis: i64) -> String {
    let seconds = millis.div_euclid(1000).rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02} UTC",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// A UTC instant in milliseconds since the Unix epoch as
/// `YYYY-MM-DD HH:MM:SS UTC`.
#[must_use]
pub fn format_instant(millis: i64) -> String {
    format!(
        "{}:{:02} UTC",
        format_timestamp(millis).trim_end_matches(" UTC"),
        millis.div_euclid(1000).rem_euclid(60)
    )
}

/// A UTC instant in milliseconds since the Unix epoch as `YYYY-MM-DD HH:MM UTC`.
#[must_use]
pub fn format_timestamp(millis: i64) -> String {
    let minutes = millis.div_euclid(60_000);
    let (days, minute_of_day) = (minutes.div_euclid(1440), minutes.rem_euclid(1440));
    // The civil date of a day count (Howard Hinnant's algorithm).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        minute_of_day / 60,
        minute_of_day % 60
    )
}

/// Milliseconds since the Unix epoch of a UTC RFC 3339 timestamp in the form
/// the harness writes (`YYYY-MM-DDTHH:MM:SS`, an optional fraction, `Z`);
/// any other text has no instant.
#[must_use]
pub fn parse_timestamp(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let rest = text.strip_suffix('Z')?;
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = rest.get(range)?;
        if digits.bytes().all(|byte| byte.is_ascii_digit()) {
            digits.parse().ok()
        } else {
            None
        }
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let fraction = rest.get(19..)?;
    let millis = match fraction.strip_prefix('.') {
        None if fraction.is_empty() => 0,
        Some(digits) if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) => {
            digits
                .bytes()
                .chain(std::iter::repeat(b'0'))
                .take(3)
                .fold(0, |value, byte| value * 10 + i64::from(byte - b'0'))
        }
        _ => return None,
    };
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return None,
    };
    if year == 0 || !(1..=month_days).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millis)
}
