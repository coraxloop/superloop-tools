//! Markdown in the agent's responses and compaction summaries, written as HTML
//! by this module alone.
//!
//! pulldown-cmark parses the text and the writer here turns its events into
//! HTML over an allowlist: paragraphs, headings moved below the page's own,
//! lists, block quotes, rules, emphasis, strong, strikethrough, inline code,
//! code blocks and tables. Every text goes through [`escape`], raw HTML is
//! written as escaped text, a link keeps its target only for `http`, `https`
//! and fragment targets, and an image is written as its description, never as
//! an image element. The result is [`Markup`], the one value the templates
//! print without escaping it.

use minijinja::Value;
use pulldown_cmark::{Alignment, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use serde::{Serialize, Serializer};

/// The Markdown extensions the writer reads: tables and strikethrough.
const OPTIONS: Options = Options::ENABLE_TABLES.union(Options::ENABLE_STRIKETHROUGH);

/// HTML this module wrote from Markdown.
///
/// Its field is private and only [`render`] makes one, so every `Markup` holds
/// the writer's output: allowlisted elements around escaped text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Markup(String);

impl Markup {
    /// The HTML text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Markup {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // The program's one pre-escaped value: the writer below escaped every
        // text it holds, so the templates print it as it is.
        Value::from_safe_string(self.0.clone()).serialize(serializer)
    }
}

/// Appends `text` escaped for HTML: `&`, `<`, `>`, `"`, `'` and `/` as
/// character references, as the template environment escapes every value.
pub fn escape(text: &str, out: &mut String) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            '/' => out.push_str("&#x2f;"),
            other => out.push(other),
        }
    }
}

/// Whether a link keeps its target: an `http` or `https` address, or a
/// fragment of the page itself.
fn kept_target(target: &str) -> bool {
    target.starts_with('#')
        || ["http://", "https://"].iter().any(|scheme| {
            target
                .get(..scheme.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
        })
}

/// The tags of a heading moved two levels down, so that a response's first
/// level sits below the page's own heading.
const fn heading(level: HeadingLevel) -> (&'static str, &'static str) {
    match level {
        HeadingLevel::H1 => ("<h3>", "</h3>\n"),
        HeadingLevel::H2 => ("<h4>", "</h4>\n"),
        HeadingLevel::H3 => ("<h5>", "</h5>\n"),
        HeadingLevel::H4 | HeadingLevel::H5 | HeadingLevel::H6 => ("<h6>", "</h6>\n"),
    }
}

/// The class a table cell carries for its column's alignment.
const fn aligned(alignment: Option<&Alignment>) -> &'static str {
    match alignment {
        Some(Alignment::Left) => " class=\"left\"",
        Some(Alignment::Center) => " class=\"center\"",
        Some(Alignment::Right) => " class=\"right\"",
        Some(Alignment::None) | None => "",
    }
}

/// The writer's state between events.
#[derive(Default)]
struct Writer {
    out: String,
    /// For each open link or image, whether its start wrote an anchor.
    links: Vec<bool>,
    /// The column alignments of the open table.
    alignments: Vec<Alignment>,
    /// Whether the open table row is the head row.
    head: bool,
    /// The index of the next cell of the open row.
    cell: usize,
}

impl Writer {
    fn push(&mut self, html: &str) {
        self.out.push_str(html);
    }

    fn text(&mut self, text: &str) {
        escape(text, &mut self.out);
    }

    fn start(&mut self, tag: &Tag<'_>) {
        match tag {
            Tag::Paragraph => self.push("<p>"),
            Tag::Heading { level, .. } => self.push(heading(*level).0),
            Tag::BlockQuote(_) => self.push("<blockquote>\n"),
            Tag::CodeBlock(_) => self.push("<pre><code>"),
            Tag::HtmlBlock => self.push("<pre class=\"html\">"),
            Tag::List(Some(1)) => self.push("<ol>\n"),
            Tag::List(Some(start)) => {
                self.push("<ol start=\"");
                self.push(&start.to_string());
                self.push("\">\n");
            }
            Tag::List(None) => self.push("<ul>\n"),
            Tag::Item => self.push("<li>"),
            Tag::Table(alignments) => {
                self.alignments.clone_from(alignments);
                self.push("<div class=\"table\"><table>\n");
            }
            Tag::TableHead => {
                self.head = true;
                self.cell = 0;
                self.push("<thead><tr>");
            }
            Tag::TableRow => {
                self.cell = 0;
                self.push("<tr>");
            }
            Tag::TableCell => {
                self.push(if self.head { "<th" } else { "<td" });
                self.push(aligned(self.alignments.get(self.cell)));
                self.push(">");
            }
            Tag::Emphasis => self.push("<em>"),
            Tag::Strong => self.push("<strong>"),
            Tag::Strikethrough => self.push("<del>"),
            Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. } => {
                let kept = kept_target(dest_url);
                if kept {
                    self.push("<a href=\"");
                    self.text(dest_url);
                    self.push("\">");
                }
                self.links.push(kept);
            }
            // The extensions the options leave off write no element.
            _ => {}
        }
    }

    fn end(&mut self, tag: TagEnd) {
        match tag {
            TagEnd::Paragraph => self.push("</p>\n"),
            TagEnd::Heading(level) => self.push(heading(level).1),
            TagEnd::BlockQuote(_) => self.push("</blockquote>\n"),
            TagEnd::CodeBlock => self.push("</code></pre>\n"),
            TagEnd::HtmlBlock => self.push("</pre>\n"),
            TagEnd::List(true) => self.push("</ol>\n"),
            TagEnd::List(false) => self.push("</ul>\n"),
            TagEnd::Item => self.push("</li>\n"),
            TagEnd::Table => self.push("</tbody></table></div>\n"),
            TagEnd::TableHead => {
                self.head = false;
                self.push("</tr></thead>\n<tbody>\n");
            }
            TagEnd::TableRow => self.push("</tr>\n"),
            TagEnd::TableCell => {
                self.push(if self.head { "</th>" } else { "</td>" });
                self.cell += 1;
            }
            TagEnd::Emphasis => self.push("</em>"),
            TagEnd::Strong => self.push("</strong>"),
            TagEnd::Strikethrough => self.push("</del>"),
            TagEnd::Link | TagEnd::Image => {
                let anchored = self.links.pop() == Some(true);
                self.push(if anchored { "</a>" } else { "" });
            }
            _ => {}
        }
    }

    fn event(&mut self, event: &Event<'_>) {
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(*tag),
            Event::Code(code) => {
                self.push("<code>");
                self.text(code);
                self.push("</code>");
            }
            Event::Text(text)
            | Event::Html(text)
            | Event::InlineHtml(text)
            | Event::InlineMath(text)
            | Event::DisplayMath(text)
            | Event::FootnoteReference(text) => self.text(text),
            Event::SoftBreak => self.push("\n"),
            Event::HardBreak => self.push("<br>\n"),
            Event::Rule => self.push("<hr>\n"),
            Event::TaskListMarker(done) => self.push(if *done { "[x] " } else { "[ ] " }),
        }
    }
}

/// Writes Markdown `text` as HTML over the allowlist.
#[must_use]
pub fn render(text: &str) -> Markup {
    let mut writer = Writer::default();
    for event in Parser::new_ext(text, OPTIONS) {
        writer.event(&event);
    }
    Markup(writer.out)
}

/// Whether a tag marks a span of text or a table cell rather than a block.
const fn is_span(tag: &Tag<'_>) -> bool {
    matches!(
        tag,
        Tag::TableCell
            | Tag::Emphasis
            | Tag::Strong
            | Tag::Strikethrough
            | Tag::Superscript
            | Tag::Subscript
            | Tag::Link { .. }
            | Tag::Image { .. }
    )
}

/// Whether a tag's end closes a span of text or a table cell.
const fn is_span_end(tag: TagEnd) -> bool {
    matches!(
        tag,
        TagEnd::TableCell
            | TagEnd::Emphasis
            | TagEnd::Strong
            | TagEnd::Strikethrough
            | TagEnd::Superscript
            | TagEnd::Subscript
            | TagEnd::Link
            | TagEnd::Image
    )
}

/// The plain text of the first block of Markdown `text` that holds any,
/// without its marks; a table's head row gives its cells joined by ` · `.
#[must_use]
pub fn first_block(text: &str) -> String {
    let mut plain = String::new();
    for event in Parser::new_ext(text, OPTIONS) {
        let boundary = match &event {
            Event::Start(Tag::TableCell) => {
                if !plain.is_empty() {
                    plain.push_str(" · ");
                }
                false
            }
            Event::Start(tag) => !is_span(tag),
            Event::End(tag) => !is_span_end(*tag),
            Event::Rule => true,
            Event::Text(text)
            | Event::Code(text)
            | Event::Html(text)
            | Event::InlineHtml(text)
            | Event::InlineMath(text)
            | Event::DisplayMath(text)
            | Event::FootnoteReference(text) => {
                plain.push_str(text);
                false
            }
            Event::SoftBreak => {
                plain.push(' ');
                false
            }
            Event::HardBreak => {
                plain.push('\n');
                false
            }
            Event::TaskListMarker(_) => false,
        };
        if boundary && !plain.trim().is_empty() {
            break;
        }
    }
    plain
}
