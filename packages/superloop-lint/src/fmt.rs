//! Mechanical Markdown formatting.
//!
//! The formatter owns one deliberately small style: every paragraph runs on
//! one line, including the inline content of a tight list item. It otherwise
//! delegates Markdown spelling to `pulldown-cmark-to-cmark`, after parsing with
//! the same extensions as the linter's document readers.
//!
//! Formatting is guarded semantically. The rendered document is parsed again,
//! and its event stream must be equivalent to the input after the one intended
//! transformation: a soft break in paragraph-like content becomes a space.
//! Text compares after whitespace normalization, while inline code, fenced
//! bodies and info strings, HTML, and link destinations compare exactly as
//! fields of their events. A failed guard records that file as a rejection in
//! either mode; write mode still applies the remaining guarded changes.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`joins_a_hard_wrapped_paragraph`] | fmt | A soft break in a paragraph becomes one space, producing one running line without moving its words. |
//! | [`formats_markdown_idempotently`] | fmt | The bytes emitted by one pass are the fixed point of the formatter, so checking the same document again reports no change. |
//! | [`preserves_a_fenced_code_block_byte_for_byte`] | fmt | A safe three-backtick fence and every byte of its body survive while prose around it is independently formatted. |
//! | [`preserves_calculus_labels_through_a_table`] | fmt | Mints, parenthesized citations, inline-code payloads, and tables pass the integrity guard with every calculus token unchanged. |
//! | [`refuses_a_word_changing_event_stream`] | fmt | The equivalence guard rejects a serializer result that changes a word, even when both sides remain valid Markdown. |
//! | [`preserves_authored_markdown_escapes`] | fmt | Source ranges retain authored escapes, so literal asterisks cannot turn into emphasis during serialization. |
//! | [`raises_every_fence_for_a_hazardous_code_block_body`] | fmt | A backtick run in one body raises the safe global fence width for every block, reflecting the serializer's file-wide option without changing a body byte. |
//! | [`preserves_authored_inline_code_delimiters`] | fmt | Display and mint inline-code spans retain their distinct authored delimiter widths and reach a fixed point. |
//! | [`preserves_a_wide_delimiter_around_a_backtick_payload`] | fmt | A code span whose payload contains a backtick retains an authored delimiter wider than the serializer would choose. |
//! | [`guard_rejections_name_matching_kind_differences`] | fmt | A guard rejection whose input and output have the same event kind names the differing attribute and the input byte range, rather than repeating the kind on both sides. |
//! | [`keeps_an_overlay_slot_atomic_between_paragraphs`] | fmt | Independently formatted paragraphs remain running lines on either side of an unchanged overlay slot without gaining blank lines. |

use std::collections::BTreeSet;
use std::fmt as std_fmt;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pulldown_cmark::{Event, Options as ParseOptions, Parser, Tag, TagEnd};
use pulldown_cmark_to_cmark::{
    Options as SerializeOptions, calculate_code_block_token_count,
    cmark_with_source_range_and_options,
};
use serde::Serialize;

/// One Markdown file changed, or found to need a change, by the formatter.
#[derive(Debug, Clone, Serialize)]
pub struct FormatChange {
    /// The path exactly as reached from the command's arguments.
    pub path: String,
    /// Wall time spent parsing, guarding, and, where enabled, writing the file.
    pub elapsed_micros: u128,
}

/// A byte range in the formatter input.
#[derive(Debug, Clone, Serialize)]
pub struct ByteRange {
    /// The first byte in the range.
    pub start: usize,
    /// One past the final byte in the range.
    pub end: usize,
}

/// One Markdown file that could not safely be formatted.
#[derive(Debug, Clone, Serialize)]
pub struct FormatRejection {
    /// The path exactly as reached from the command's arguments.
    pub path: String,
    /// The stable category of the failure.
    pub kind: String,
    /// The reason the file could not be safely formatted.
    pub cause: String,
    /// The first guard event whose input and output differed, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_index: Option<usize>,
    /// What differed at that guard event, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difference: Option<String>,
    /// The byte range in the input for the differing guard event, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_range: Option<ByteRange>,
    /// Wall time spent reading, parsing, guarding, and recording the rejection.
    pub elapsed_micros: u128,
}

/// The stdout result object of the `fmt` command.
#[derive(Debug, Clone, Serialize)]
pub struct FormatReport {
    /// Whether the command only checked for changes.
    pub check: bool,
    /// How many Markdown files were considered.
    pub files_scanned: usize,
    /// How many files changed or would change.
    pub files_changed: usize,
    /// How many files could not safely be formatted.
    pub files_rejected: usize,
    /// Every changed path, in deterministic path order, with its action time.
    pub changed: Vec<FormatChange>,
    /// Every rejection in deterministic path order.
    pub rejected: Vec<FormatRejection>,
    /// Wall time for discovery, formatting, guarding, and optional writes.
    pub elapsed_micros: u128,
}

impl FormatReport {
    /// Whether at least one file changed, would change, or was rejected.
    #[must_use]
    pub const fn has_changes(&self) -> bool {
        self.files_changed != 0 || self.files_rejected != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuardRejection {
    event_index: usize,
    difference: String,
    input_range: Range<usize>,
}

impl std_fmt::Display for GuardRejection {
    fn fmt(&self, formatter: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        write!(
            formatter,
            "integrity guard rejected event {}: {}; input bytes {}..{}",
            self.event_index, self.difference, self.input_range.start, self.input_range.end
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FormatErrorKind {
    Other,
    Guard(GuardRejection),
}

/// A command failure from traversal, writing, or a formatter request error.
///
/// Per-file read, source-parse, and integrity-guard failures are recorded as
/// `FormatRejection` values instead, allowing the formatter to continue through
/// the rest of the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatError {
    message: String,
    kind: FormatErrorKind,
}

impl FormatError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: FormatErrorKind::Other,
        }
    }

    fn guard(rejection: GuardRejection) -> Self {
        Self {
            message: rejection.to_string(),
            kind: FormatErrorKind::Guard(rejection),
        }
    }

    fn at(path: &Path, message: impl std_fmt::Display) -> Self {
        Self::new(format!("{}: {message}", path.display()))
    }

    const fn guard_rejection(&self) -> Option<&GuardRejection> {
        match &self.kind {
            FormatErrorKind::Other => None,
            FormatErrorKind::Guard(rejection) => Some(rejection),
        }
    }
}

impl std_fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for FormatError {}

struct PlannedWrite {
    path: PathBuf,
    rendered: String,
    elapsed: Duration,
}

/// Format every Markdown file named by `paths` or found below their directories.
///
/// Directories are walked recursively without following symbolic links. Files
/// reached through directories must have the lowercase `.md` extension; a path
/// naming a file directly must name such a file as well. All inputs are parsed,
/// serialized, and guarded before the first write, so an unsafe document cannot
/// leave an otherwise successful plan half-applied.
///
/// A file that cannot be read, or whose output the equivalence guard refuses, is
/// recorded as a rejection in both modes and costs the remaining files nothing.
/// A run judges each file on its own: the alternative, refusing the whole
/// request over one unformattable document, makes a tree exactly as formattable
/// as its worst file and leaves a caller no way to make progress on the rest.
///
/// # Errors
///
/// Returns an error when a path cannot be traversed or when a write fails.
pub fn format_paths(paths: &[PathBuf], check: bool) -> Result<FormatReport, FormatError> {
    let started = Instant::now();
    let files = markdown_files(paths)?;
    let files_scanned = files.len();
    let mut planned = Vec::new();
    let mut rejected = Vec::new();

    for path in files {
        let file_started = Instant::now();
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                let kind = if error.kind() == std::io::ErrorKind::InvalidData {
                    "source_parse_failure"
                } else {
                    "read_failure"
                };
                let cause = format!("could not read: {error}");

                rejected.push(FormatRejection {
                    path: path.to_string_lossy().into_owned(),
                    kind: kind.to_owned(),
                    cause,
                    event_index: None,
                    difference: None,
                    input_range: None,
                    elapsed_micros: file_started.elapsed().as_micros(),
                });
                continue;
            }
        };
        let rendered = match format_markdown(&source) {
            Ok(rendered) => rendered,
            Err(error) => {
                let (kind, cause, event_index, difference, input_range) =
                    error.guard_rejection().map_or_else(
                        || ("source_parse_failure", error.to_string(), None, None, None),
                        |rejection| {
                            (
                                "integrity_guard",
                                error.to_string(),
                                Some(rejection.event_index),
                                Some(rejection.difference.clone()),
                                Some(ByteRange {
                                    start: rejection.input_range.start,
                                    end: rejection.input_range.end,
                                }),
                            )
                        },
                    );
                rejected.push(FormatRejection {
                    path: path.to_string_lossy().into_owned(),
                    kind: kind.to_owned(),
                    cause,
                    event_index,
                    difference,
                    input_range,
                    elapsed_micros: file_started.elapsed().as_micros(),
                });
                continue;
            }
        };

        if rendered != source {
            planned.push(PlannedWrite {
                path,
                rendered,
                elapsed: file_started.elapsed(),
            });
        }
    }

    let mut changed = Vec::with_capacity(planned.len());

    for mut change in planned {
        if !check {
            let write_started = Instant::now();
            fs::write(&change.path, &change.rendered).map_err(|error| {
                FormatError::at(&change.path, format_args!("could not write: {error}"))
            })?;
            change.elapsed += write_started.elapsed();
        }

        changed.push(FormatChange {
            path: change.path.to_string_lossy().into_owned(),
            elapsed_micros: change.elapsed.as_micros(),
        });
    }

    Ok(FormatReport {
        check,
        files_scanned,
        files_changed: changed.len(),
        files_rejected: rejected.len(),
        changed,
        rejected,
        elapsed_micros: started.elapsed().as_micros(),
    })
}

/// Format one Markdown document in memory.
///
/// A source ending in a newline keeps one after serialization. The serializer
/// itself defers block spacing until another event arrives and would otherwise
/// discard that ordinary end-of-file terminator.
///
/// # Errors
///
/// Returns an error when the serializer rejects the parser's event stream or
/// when re-parsing proves that the rendered stream is not equivalent.
pub fn format_markdown(source: &str) -> Result<String, FormatError> {
    let slots = overlay_slot_lines(source);
    let mut rendered = if slots.is_empty() {
        serialize_markdown(source)?
    } else {
        serialize_around_slots(source, &slots)?
    };

    if source.ends_with('\n') && !rendered.ends_with('\n') {
        rendered.push('\n');
    }

    ensure_equivalent(source, &rendered)?;
    Ok(rendered)
}

fn serialize_markdown(source: &str) -> Result<String, FormatError> {
    let protected = protect_code_pipes(source);
    validate_table_rows(source, &protected)?;
    let parsed: Vec<_> = Parser::new_ext(&protected, parser_options())
        .into_offset_iter()
        .collect();
    let fence_width = calculate_code_block_token_count(parsed.iter().map(|(event, _range)| event))
        .unwrap_or(3)
        .max(3);
    let events = reflow_soft_breaks(source, parsed);
    let mut rendered = String::new();

    cmark_with_source_range_and_options(
        events
            .iter()
            .map(|(event, range)| (event, Some(range.clone()))),
        source,
        &mut rendered,
        serializer_options(fence_width),
    )
    .map_err(|error| FormatError::new(format!("could not serialize Markdown: {error}")))?;

    Ok(rendered)
}

/// Hide code-span pipes from the table block parser without moving offsets.
/// Each physical row pairs its own backticks, so a stray delimiter cannot consume
/// the opening delimiter in the next row. Output still uses the original bytes.
fn protect_code_pipes(source: &str) -> String {
    let mut protected = source.to_owned();
    let paragraphs = Parser::new_ext(source, parser_options() - ParseOptions::ENABLE_TABLES)
        .into_offset_iter()
        .filter_map(|(event, range)| {
            matches!(event, Event::Start(Tag::Paragraph)).then_some(range)
        });
    for paragraph in paragraphs {
        let mut start = paragraph.start;
        for row in source[paragraph].split_inclusive('\n') {
            for (event, range) in
                Parser::new_ext(row, parser_options() - ParseOptions::ENABLE_TABLES)
                    .into_offset_iter()
            {
                if matches!(event, Event::Code(_)) {
                    for (offset, byte) in row[range.clone()].bytes().enumerate() {
                        if byte == b'|' {
                            let at = start + range.start + offset;
                            protected.replace_range(at..=at, "x");
                        }
                    }
                }
            }
            start += row.len();
        }
    }
    protected
}

/// Refuse shapes for which the table parser would discard cells or infer a new
/// table boundary. Incomplete masked rows are ambiguous across cell boundaries.
fn validate_table_rows(source: &str, protected: &str) -> Result<(), FormatError> {
    let tables = |text| {
        Parser::new_ext(text, parser_options())
            .into_offset_iter()
            .filter_map(|(event, range)| match event {
                Event::Start(Tag::Table(columns)) => Some((range, columns.len())),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let original = tables(source);
    let masked = tables(protected);
    if original
        .iter()
        .map(|(range, _)| range.start)
        .collect::<Vec<_>>()
        != masked
            .iter()
            .map(|(range, _)| range.start)
            .collect::<Vec<_>>()
    {
        return Err(FormatError::new(
            "table-code-pipe-header: masking changes header/delimiter table recognition",
        ));
    }
    for (range, columns) in masked {
        let mut start = range.start;
        for (index, row) in protected[range].split_inclusive('\n').enumerate() {
            if index != 1 {
                let count = table_cell_count(row);
                let raw = &source[start..start + row.len()];
                if count > columns || (raw != row && count < columns) {
                    return Err(FormatError::new(format!(
                        "table-code-pipe-row: row {:?} at byte {start} has {count} cells for {columns} columns",
                        raw.trim()
                    )));
                }
            }
            start += row.len();
        }
    }
    Ok(())
}

fn table_cell_count(row: &str) -> usize {
    let row = row.trim();
    let mut separators = Vec::new();
    let mut escaped = false;
    for (offset, byte) in row.bytes().enumerate() {
        if byte == b'|' && !escaped {
            separators.push(offset);
        }
        escaped = byte == b'\\' && !escaped;
    }
    separators.len() + 1
        - usize::from(separators.first() == Some(&0))
        - usize::from(separators.last() == row.len().checked_sub(1).as_ref())
}

fn serialize_around_slots(source: &str, slots: &[Range<usize>]) -> Result<String, FormatError> {
    let mut rendered = String::new();
    let mut prose_start = 0usize;

    for slot in slots {
        rendered.push_str(&serialize_slot_bounded_prose(
            &source[prose_start..slot.start],
            prose_start != 0,
            true,
        )?);
        rendered.push_str(&source[slot.clone()]);
        prose_start = slot.end;
    }

    rendered.push_str(&serialize_slot_bounded_prose(
        &source[prose_start..],
        true,
        false,
    )?);
    Ok(rendered)
}

fn serialize_slot_bounded_prose(
    source: &str,
    preserve_leading_breaks: bool,
    preserve_trailing_breaks: bool,
) -> Result<String, FormatError> {
    let is_break = |character: char| matches!(character, '\r' | '\n');
    let content_start = if preserve_leading_breaks {
        source.len() - source.trim_start_matches(is_break).len()
    } else {
        0
    };
    let content_end = if preserve_trailing_breaks {
        source.trim_end_matches(is_break).len()
    } else {
        source.len()
    };

    if content_start > content_end {
        return Ok(source.to_owned());
    }

    let mut rendered = String::from(&source[..content_start]);
    rendered.push_str(&serialize_markdown(&source[content_start..content_end])?);
    rendered.push_str(&source[content_end..]);
    Ok(rendered)
}

/// Locate whole-line overlay slots using the grammar of `superloop_install::slot_label`.
fn overlay_slot_lines(source: &str) -> Vec<Range<usize>> {
    let mut slots = Vec::new();
    let mut start = 0usize;

    for line in source.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let body = body.strip_suffix('\r').unwrap_or(body);

        if is_overlay_slot(body.as_bytes()) {
            slots.push(start..start + line.len());
        }

        start += line.len();
    }

    slots
}

fn is_overlay_slot(line: &[u8]) -> bool {
    let Some(label) = line
        .strip_prefix(b"{{overlay:")
        .and_then(|rest| rest.strip_suffix(b"}}"))
    else {
        return false;
    };
    let mut colons = 0usize;
    let mut segment_length = 0usize;

    for byte in label {
        if *byte == b':' {
            if segment_length == 0 {
                return false;
            }
            colons += 1;
            segment_length = 0;
        } else if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_') {
            segment_length += 1;
        } else {
            return false;
        }
    }

    colons >= 2 && segment_length > 0
}

fn parser_options() -> ParseOptions {
    ParseOptions::ENABLE_TABLES
        | ParseOptions::ENABLE_FOOTNOTES
        | ParseOptions::ENABLE_STRIKETHROUGH
        | ParseOptions::ENABLE_TASKLISTS
}

const fn serializer_options(code_block_token_count: usize) -> SerializeOptions<'static> {
    SerializeOptions {
        // These blocks do not emit a trailing newline themselves. Two newlines
        // therefore mean one normalized blank line before the next block.
        newlines_after_headline: 2,
        newlines_after_paragraph: 2,
        newlines_after_codeblock: 2,
        newlines_after_table: 2,
        newlines_after_rule: 2,
        newlines_after_list: 2,
        newlines_after_blockquote: 2,
        // HTML and metadata events already emit their authored final newline;
        // one deferred newline gives them the same single blank-line boundary.
        newlines_after_htmlblock: 1,
        newlines_after_metadata: 1,
        // Rows, items, and other internal boundaries stay adjacent.
        newlines_after_rest: 1,
        // Three backticks are the standard. One hazardous body raises this one
        // global width for every fence because that is the upstream API's unit.
        code_block_token_count,
        code_block_token: '`',
        list_token: '-',
        ordered_list_token: '.',
        increment_ordered_list_bullets: true,
        emphasis_token: '*',
        strong_token: "**",
        use_html_for_super_sub_script: true,
    }
}

fn reflow_soft_breaks<'a>(
    source: &'a str,
    parsed: Vec<(Event<'a>, Range<usize>)>,
) -> Vec<(Event<'a>, Range<usize>)> {
    let mut heading_depth = 0usize;
    let mut table_depth = 0usize;
    let mut reflowed = Vec::with_capacity(parsed.len());

    for (event, range) in parsed {
        match &event {
            Event::Start(Tag::Heading { .. }) => heading_depth += 1,
            Event::Start(Tag::Table(_)) => table_depth += 1,
            _ => {}
        }

        let event = if matches!(&event, Event::SoftBreak) && heading_depth == 0 && table_depth == 0
        {
            Event::Text(" ".into())
        } else {
            event
        };

        match &event {
            Event::End(TagEnd::Heading(_)) => heading_depth = heading_depth.saturating_sub(1),
            Event::End(TagEnd::Table) => table_depth = table_depth.saturating_sub(1),
            _ => {}
        }

        let event = match event {
            Event::Code(_) => Event::InlineHtml(source[range.clone()].into()),
            event => event,
        };

        reflowed.push((event, range));
    }

    reflowed
}

fn markdown_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>, FormatError> {
    let mut pending: Vec<PathBuf> = paths.iter().rev().cloned().collect();
    let mut files = BTreeSet::new();

    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| FormatError::at(&path, format_args!("could not inspect: {error}")))?;

        if metadata.file_type().is_symlink() {
            return Err(FormatError::at(
                &path,
                "symbolic links are not followed by the formatter",
            ));
        }

        if metadata.is_file() {
            if !is_markdown(&path) {
                return Err(FormatError::at(&path, "expected a Markdown file"));
            }
            files.insert(path);
            continue;
        }

        if !metadata.is_dir() {
            return Err(FormatError::at(&path, "expected a file or directory"));
        }

        let entries = fs::read_dir(&path)
            .map_err(|error| FormatError::at(&path, format_args!("could not read: {error}")))?;
        let mut children = Vec::new();

        for entry in entries {
            let entry = entry.map_err(|error| {
                FormatError::at(&path, format_args!("could not read an entry: {error}"))
            })?;
            let file_type = entry.file_type().map_err(|error| {
                FormatError::at(&entry.path(), format_args!("could not inspect: {error}"))
            })?;

            if file_type.is_dir() || (file_type.is_file() && is_markdown(&entry.path())) {
                children.push(entry.path());
            }
        }

        children.sort();
        pending.extend(children.into_iter().rev());
    }

    Ok(files.into_iter().collect())
}

fn is_markdown(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "md")
}

#[derive(Debug, PartialEq, Eq)]
enum GuardEvent {
    Structure(String),
    Text(String),
    Code {
        text: String,
        delimiter_width: usize,
    },
    CodeBlockText(String),
    Html(String),
    InlineHtml(String),
}

impl GuardEvent {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Structure(_) => "structure",
            Self::Text(_) => "text",
            Self::Code { .. } => "inline code",
            Self::CodeBlockText(_) => "code-block body",
            Self::Html(_) => "HTML block",
            Self::InlineHtml(_) => "inline HTML",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct GuardedEvent {
    event: GuardEvent,
    range: Range<usize>,
}

fn ensure_equivalent(input: &str, output: &str) -> Result<(), FormatError> {
    let input_events = guarded_events(input);
    let output_events = guarded_events(output);

    if input_events
        .iter()
        .map(|event| &event.event)
        .eq(output_events.iter().map(|event| &event.event))
    {
        return Ok(());
    }

    let mismatch = input_events
        .iter()
        .zip(&output_events)
        .position(|(left, right)| left.event != right.event)
        .unwrap_or_else(|| input_events.len().min(output_events.len()));
    let input_range = input_events
        .get(mismatch)
        .map_or(input.len()..input.len(), |event| event.range.clone());
    let rejection = GuardRejection {
        event_index: mismatch,
        difference: guard_difference(
            input_events.get(mismatch).map(|event| &event.event),
            output_events.get(mismatch).map(|event| &event.event),
        ),
        input_range,
    };

    Err(FormatError::guard(rejection))
}

fn guard_difference(input: Option<&GuardEvent>, output: Option<&GuardEvent>) -> String {
    let input_kind = input.map_or("end of stream", GuardEvent::kind);
    let output_kind = output.map_or("end of stream", GuardEvent::kind);

    if input_kind != output_kind {
        return format!("kind differs: input has {input_kind}, output has {output_kind}");
    }

    match (input, output) {
        (
            Some(GuardEvent::Code {
                delimiter_width: input_width,
                ..
            }),
            Some(GuardEvent::Code {
                delimiter_width: output_width,
                ..
            }),
        ) if input_width != output_width => {
            format!("delimiter width differs: input has {input_width}, output has {output_width}")
        }
        (
            Some(GuardEvent::Code {
                text: input_text, ..
            }),
            Some(GuardEvent::Code {
                text: output_text, ..
            }),
        ) => value_difference("inline code text", input_text, output_text),
        (Some(GuardEvent::Text(input)), Some(GuardEvent::Text(output))) => {
            value_difference("text", input, output)
        }
        (Some(GuardEvent::Structure(input)), Some(GuardEvent::Structure(output))) => {
            value_difference("attribute", input, output)
        }
        (Some(GuardEvent::CodeBlockText(input)), Some(GuardEvent::CodeBlockText(output))) => {
            value_difference("code-block body", input, output)
        }
        (Some(GuardEvent::Html(input)), Some(GuardEvent::Html(output))) => {
            value_difference("HTML block", input, output)
        }
        (Some(GuardEvent::InlineHtml(input)), Some(GuardEvent::InlineHtml(output))) => {
            value_difference("inline HTML", input, output)
        }
        _ => format!("stream length differs: input has {input_kind}, output has {output_kind}"),
    }
}

fn value_difference(name: &str, input: &str, output: &str) -> String {
    format!(
        "{name} differs: input {}, output {}",
        bounded_value_preview(input),
        bounded_value_preview(output)
    )
}

fn bounded_value_preview(value: &str) -> String {
    const LIMIT: usize = 80;

    let mut preview = String::new();
    let mut truncated = false;

    for (index, character) in value.chars().enumerate() {
        if index == LIMIT {
            truncated = true;
            break;
        }

        preview.push(character);
    }

    if truncated {
        preview.push_str("...");
        format!("starts with {preview:?}")
    } else {
        format!("is {preview:?}")
    }
}

fn guarded_events(source: &str) -> Vec<GuardedEvent> {
    let protected = protect_code_pipes(source);
    let mut guarded = Vec::new();
    let mut pending_text = String::new();
    let mut pending_text_range: Option<Range<usize>> = None;
    let mut code_block_depth = 0usize;
    let mut heading_depth = 0usize;
    let mut table_depth = 0usize;

    for (event, range) in Parser::new_ext(&protected, parser_options()).into_offset_iter() {
        match &event {
            Event::Start(Tag::Heading { .. }) => heading_depth += 1,
            Event::Start(Tag::Table(_)) => table_depth += 1,
            _ => {}
        }

        match &event {
            Event::Start(Tag::CodeBlock(_)) => {
                flush_text(&mut pending_text, &mut pending_text_range, &mut guarded);
                push_guarded(
                    &mut guarded,
                    GuardEvent::Structure(format!("{event:?}")),
                    range,
                );
                code_block_depth += 1;
            }
            Event::End(TagEnd::CodeBlock) => {
                flush_text(&mut pending_text, &mut pending_text_range, &mut guarded);
                code_block_depth = code_block_depth.saturating_sub(1);
                push_guarded(
                    &mut guarded,
                    GuardEvent::Structure(format!("{event:?}")),
                    range,
                );
            }
            Event::Text(text) if code_block_depth != 0 => {
                flush_text(&mut pending_text, &mut pending_text_range, &mut guarded);
                push_code_block_text(&mut guarded, text, range);
            }
            Event::Text(text) => {
                push_pending_text(&mut pending_text, &mut pending_text_range, text, range);
            }
            Event::SoftBreak if heading_depth == 0 && table_depth == 0 => {
                push_pending_text(&mut pending_text, &mut pending_text_range, " ", range);
            }
            Event::Code(_) => {
                flush_text(&mut pending_text, &mut pending_text_range, &mut guarded);
                let delimiter_width = source[range.clone()]
                    .bytes()
                    .take_while(|byte| *byte == b'`')
                    .count();
                push_guarded(
                    &mut guarded,
                    GuardEvent::Code {
                        text: source[range.clone()].to_owned(),
                        delimiter_width,
                    },
                    range,
                );
            }
            Event::Html(text) => {
                flush_text(&mut pending_text, &mut pending_text_range, &mut guarded);
                push_guarded(&mut guarded, GuardEvent::Html(text.to_string()), range);
            }
            Event::InlineHtml(text) => {
                flush_text(&mut pending_text, &mut pending_text_range, &mut guarded);
                push_guarded(
                    &mut guarded,
                    GuardEvent::InlineHtml(text.to_string()),
                    range,
                );
            }
            _ => {
                flush_text(&mut pending_text, &mut pending_text_range, &mut guarded);
                push_guarded(
                    &mut guarded,
                    GuardEvent::Structure(format!("{event:?}")),
                    range,
                );
            }
        }

        match &event {
            Event::End(TagEnd::Heading(_)) => heading_depth = heading_depth.saturating_sub(1),
            Event::End(TagEnd::Table) => table_depth = table_depth.saturating_sub(1),
            _ => {}
        }
    }

    flush_text(&mut pending_text, &mut pending_text_range, &mut guarded);
    guarded
}

fn push_guarded(guarded: &mut Vec<GuardedEvent>, event: GuardEvent, range: Range<usize>) {
    guarded.push(GuardedEvent { event, range });
}

fn push_pending_text(
    pending: &mut String,
    pending_range: &mut Option<Range<usize>>,
    text: &str,
    range: Range<usize>,
) {
    if pending.is_empty() {
        *pending_range = Some(range);
    } else if let Some(pending_range) = pending_range.as_mut() {
        pending_range.end = range.end;
    }
    pending.push_str(text);
}

fn flush_text(
    pending: &mut String,
    pending_range: &mut Option<Range<usize>>,
    guarded: &mut Vec<GuardedEvent>,
) {
    if pending.is_empty() {
        return;
    }

    let mut words = pending.split_whitespace();
    let mut normalized = words.next().unwrap_or_default().to_owned();
    for word in words {
        normalized.push(' ');
        normalized.push_str(word);
    }
    pending.clear();

    if normalized.is_empty() {
        *pending_range = None;
    } else {
        guarded.push(GuardedEvent {
            event: GuardEvent::Text(normalized),
            range: pending_range.take().unwrap_or(0..0),
        });
    }
}

fn push_code_block_text(guarded: &mut Vec<GuardedEvent>, text: &str, range: Range<usize>) {
    if let Some(GuardedEvent {
        event: GuardEvent::CodeBlockText(current),
        range: current_range,
    }) = guarded.last_mut()
    {
        current.push_str(text);
        current_range.end = range.end;
    } else {
        push_guarded(guarded, GuardEvent::CodeBlockText(text.to_owned()), range);
    }
}

#[cfg(test)]
mod tests {
    use super::{bounded_value_preview, ensure_equivalent, format_markdown};

    fn formatted(source: &str) -> String {
        match format_markdown(source) {
            Ok(rendered) => rendered,
            Err(error) => panic!("formatting failed: {error}"),
        }
    }

    /// A soft break in a paragraph becomes one space, producing one running
    /// line without moving its words.
    ///
    /// ´claim:fmt:a-soft-break-formats-as-one-space-without-moving-words´
    /// ´test:unit:joins-a-hard-wrapped-paragraph´
    #[test]
    fn joins_a_hard_wrapped_paragraph() {
        let source = "A paragraph that is\nhard wrapped.\n";
        assert_eq!(formatted(source), "A paragraph that is hard wrapped.\n");
    }

    /// The bytes emitted by one pass are the fixed point of the formatter, so
    /// checking the same document again reports no change.
    ///
    /// ´claim:fmt:one-pass-is-the-formatters-fixed-point´
    /// ´test:unit:formats-markdown-idempotently´
    #[test]
    fn formats_markdown_idempotently() {
        let once = formatted("One line that was\nwrapped by hand.\n");
        let twice = formatted(&once);
        assert_eq!(once, twice);
    }

    /// A safe three-backtick fence and every byte of its body survive while
    /// prose around it is independently formatted.
    ///
    /// ´claim:fmt:a-safe-fence-and-its-body-survive-formatting´
    /// ´test:unit:preserves-a-fenced-code-block-byte-for-byte´
    #[test]
    fn preserves_a_fenced_code_block_byte_for_byte() {
        let block = "```rust\nlet value = `literal`;\n```";
        let source = format!("Before the block.\n\n{block}\n\nAfter the block.\n");
        let rendered = formatted(&source);
        assert!(rendered.contains(block));
    }

    /// Mints, parenthesized citations, inline-code payloads, and tables pass
    /// the integrity guard with every calculus token unchanged.
    ///
    /// ´claim:fmt:calculus-tokens-survive-formatting-unchanged´
    /// ´test:unit:preserves-calculus-labels-through-a-table´
    #[test]
    fn preserves_calculus_labels_through_a_table() {
        let source = concat!(
            "## Head · `sec:area:head`\n\n",
            "The citation (`sec:area:head`) and mint · `claim:area:statement` survive.\n\n",
            "| Form | Label |\n",
            "| --- | --- |\n",
            "| code | `kind:area:slug` |\n",
        );
        let rendered = formatted(source);

        for exact in [
            "· `sec:area:head`",
            "(`sec:area:head`)",
            "· `claim:area:statement`",
            "`kind:area:slug`",
        ] {
            assert!(rendered.contains(exact), "missing exact span {exact}");
        }
    }

    /// The equivalence guard rejects a serializer result that changes a word,
    /// even when both sides remain valid Markdown.
    ///
    /// ´claim:fmt:word-changing-markdown-is-refused-by-the-equivalence-guard´
    /// ´test:unit:refuses-a-word-changing-event-stream´
    #[test]
    fn refuses_a_word_changing_event_stream() {
        let result = ensure_equivalent("The original word.\n", "The changed word.\n");
        assert!(result.is_err());
    }

    /// Source ranges retain authored escapes, so literal asterisks cannot turn
    /// into emphasis during serialization.
    ///
    /// ´claim:fmt:authored-escapes-survive-serialization´
    /// ´test:unit:preserves-authored-markdown-escapes´
    #[test]
    fn preserves_authored_markdown_escapes() {
        let source = "An authored \\*literal\\* stays text.\n";
        assert_eq!(formatted(source), source);
    }

    /// A backtick run in one body raises the safe global fence width for every
    /// block, reflecting the serializer's file-wide option without changing a
    /// body byte.
    ///
    /// ´claim:fmt:a-hazardous-body-raises-every-fence-without-changing-body-bytes´
    /// ´test:unit:raises-every-fence-for-a-hazardous-code-block-body´
    #[test]
    fn raises_every_fence_for_a_hazardous_code_block_body() {
        let source = concat!("```text\nplain\n```\n\n", "````text\n```\n````\n",);
        let rendered = formatted(source);

        assert_eq!(rendered.matches("````").count(), 4);
        assert!(rendered.contains("````text\n```\n````"));
    }

    /// Display and mint inline-code spans retain their distinct authored delimiter widths and reach a fixed point.
    ///
    /// ´claim:fmt:inline-code-preserves-authored-delimiter-width´
    /// ´test:unit:preserves-authored-inline-code-delimiters´
    #[test]
    fn preserves_authored_inline_code_delimiters() {
        let source = "The display ``kind:area:slug`` sits beside the mint · `kind:area:mint`.\n";
        let once = formatted(source);

        assert_eq!(once, source);
        assert_eq!(formatted(&once), once);
    }

    /// A code span whose payload contains a backtick retains an authored delimiter wider than the serializer would choose.
    ///
    /// ´claim:fmt:a-backtick-payload-keeps-its-authored-delimiter-width´
    /// ´test:unit:preserves-a-wide-delimiter-around-a-backtick-payload´
    #[test]
    fn preserves_a_wide_delimiter_around_a_backtick_payload() {
        let source = "The payload ```kind:`slug``` keeps its wider delimiter.\n";
        let once = formatted(source);

        assert_eq!(once, source);
        assert_eq!(formatted(&once), once);
    }

    /// A guard rejection whose input and output have the same event kind names
    /// the differing attribute and the input byte range, rather than repeating
    /// the kind on both sides.
    ///
    /// ´claim:fmt:a-guard-rejection-names-matching-kind-differences´
    /// ´test:unit:guard-rejections-name-matching-kind-differences´
    #[test]
    fn guard_rejections_name_matching_kind_differences() {
        let result = ensure_equivalent("Text ``span``.\n", "Text `span`.\n");
        let message = result.expect_err("the guard rejects delimiter-width drift");
        let message = message.to_string();

        assert!(
            message.contains("delimiter width differs"),
            "the message names the attribute: {message}"
        );
        assert!(
            message.contains("input bytes 5..13"),
            "the message names the input byte range: {message}"
        );

        let boundary =
            "01234567890123456789012345678901234567890123456789012345678901234567890123456789";
        let truncated = format!("{boundary}x");

        assert_eq!(
            bounded_value_preview(boundary),
            "is \"01234567890123456789012345678901234567890123456789012345678901234567890123456789\""
        );
        assert_eq!(
            bounded_value_preview(&truncated),
            "starts with \"01234567890123456789012345678901234567890123456789012345678901234567890123456789...\""
        );
    }

    /// Independently formatted paragraphs remain running lines on either side of an unchanged overlay slot without gaining blank lines.
    ///
    /// ´claim:fmt:an-overlay-slot-is-an-atomic-line-between-independent-prose´
    /// ´test:unit:keeps-an-overlay-slot-atomic-between-paragraphs´
    #[test]
    fn keeps_an_overlay_slot_atomic_between_paragraphs() {
        let source = "The first paragraph is\nhard wrapped.\n{{overlay:sec:fixture:slot}}\nThe second paragraph is\nhard wrapped.\n";
        let expected = "The first paragraph is hard wrapped.\n{{overlay:sec:fixture:slot}}\nThe second paragraph is hard wrapped.\n";
        let once = formatted(source);

        assert_eq!(once, expected);
        assert_eq!(formatted(&once), once);
    }
}
