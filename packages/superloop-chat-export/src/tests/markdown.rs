use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use super::super::markdown::{first_block, render};
use super::super::templates::{self, TEMPLATES};
use super::super::view::Rendered;
use super::fixture_projects;
use super::render::{html_files, render as render_loop};

/// The elements the Markdown writer makes.
const WRITER_ELEMENTS: [&str; 24] = [
    "a",
    "blockquote",
    "br",
    "code",
    "del",
    "div",
    "em",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "li",
    "ol",
    "p",
    "pre",
    "strong",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
];

/// The elements the templates make.
const TEMPLATE_ELEMENTS: [&str; 38] = [
    "a", "article", "body", "button", "dd", "details", "div", "dl", "dt", "footer", "h1", "h2",
    "h3", "head", "header", "html", "iframe", "li", "link", "main", "meta", "nav", "ol", "p",
    "script", "section", "span", "strong", "summary", "table", "tbody", "td", "th", "thead",
    "time", "title", "tr", "ul",
];

/// The names of the elements `html` opens.
fn elements(html: &str) -> BTreeSet<String> {
    html.match_indices('<')
        .map(|(at, _)| {
            html[at + 1..]
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect::<String>()
        })
        .filter(|name| name.starts_with(|first: char| first.is_ascii_lowercase()))
        .collect()
}

/// The tags `html` opens, from `<` to `>`.
fn tags(html: &str) -> Vec<&str> {
    html.match_indices('<')
        .filter(|(at, _)| html[at + 1..].starts_with(|first: char| first.is_ascii_lowercase()))
        .filter_map(|(at, _)| html[at..].find('>').map(|end| &html[at..=at + end]))
        .collect()
}

/// Whether a tag carries an event-handler attribute: ` on`, letters and `=`
/// outside every quoted value.
fn handler(tag: &str) -> bool {
    let mut outside = String::new();
    let mut quoted = false;
    for character in tag.chars() {
        if character == '"' {
            quoted = !quoted;
        } else if !quoted {
            outside.push(character);
        }
    }
    outside.match_indices(" on").any(|(at, _)| {
        let rest = &outside[at + 3..];
        let letters = rest
            .find(|character: char| !character.is_ascii_lowercase())
            .unwrap_or(rest.len());
        letters > 0 && rest[letters..].starts_with('=')
    })
}

/// The `href` values of `html`, as written.
fn hrefs(html: &str) -> Vec<&str> {
    html.split("href=\"")
        .skip(1)
        .filter_map(|rest| rest.split_once('"').map(|(value, _)| value))
        .collect()
}

const DOCUMENT: &str = "# One <script>alert(\"h1\")</script>
## Two <x>
### Three <x>
#### Four <x>

A paragraph with *emphasis <b>*, **strong <b>**, ~~struck <b>~~ and `code <i>`,\\
then a hard break.

> A quote with <em>inline html</em>.

- one <x>
- two

3. three <x>
4. four

---

<div onclick=\"alert('block')\">raw block</div>

[web](https://example.test/a?b=1&c=2) [plain](HTTP://example.test) [here](#r-1)
[script](javascript:alert(1)) [data](data:text/html,x) [file](file:///etc/passwd) [relative](notes/page.html)
![picture <x>](https://example.test/p.png) ![local](p.png)

| Name <x> | Size |
|:-----|-----:|
| a<b | 1 |

```rust
fn main() { \"<tag>\" }
```
";

/// ´test:crate:the-markdown-writer-keeps-its-allowlist-and-escapes-the-rest´
#[test]
fn the_markdown_writer_keeps_its_allowlist_and_escapes_the_rest() {
    let markup = render(DOCUMENT);
    let html = markup.as_str();
    for expected in [
        "<h3>One &lt;script&gt;alert(&quot;h1&quot;)&lt;&#x2f;script&gt;</h3>\n",
        "<h4>Two &lt;x&gt;</h4>\n<h5>Three &lt;x&gt;</h5>\n<h6>Four &lt;x&gt;</h6>\n",
        "<p>A paragraph with <em>emphasis &lt;b&gt;</em>, <strong>strong &lt;b&gt;</strong>, <del>struck &lt;b&gt;</del> and <code>code &lt;i&gt;</code>,<br>\nthen a hard break.</p>\n",
        "<blockquote>\n<p>A quote with &lt;em&gt;inline html&lt;&#x2f;em&gt;.</p>\n</blockquote>\n",
        "<ul>\n<li>one &lt;x&gt;</li>\n<li>two</li>\n</ul>\n",
        "<ol start=\"3\">\n<li>three &lt;x&gt;</li>\n<li>four</li>\n</ol>\n<hr>\n",
        "<pre class=\"html\">&lt;div onclick=&quot;alert(&#x27;block&#x27;)&quot;&gt;raw block&lt;&#x2f;div&gt;\n</pre>\n",
        "\nscript data file relative\n",
        "<a href=\"https:&#x2f;&#x2f;example.test&#x2f;p.png\">picture &lt;x&gt;</a> local</p>\n",
        "<div class=\"table\"><table>\n<thead><tr><th class=\"left\">Name &lt;x&gt;</th><th class=\"right\">Size</th></tr></thead>\n<tbody>\n<tr><td class=\"left\">a&lt;b</td><td class=\"right\">1</td></tr>\n</tbody></table></div>\n",
        "<pre><code>fn main() { &quot;&lt;tag&gt;&quot; }\n</code></pre>\n",
    ] {
        assert!(html.contains(expected), "{expected}\n{html}");
    }
    assert_eq!(
        hrefs(html),
        [
            "https:&#x2f;&#x2f;example.test&#x2f;a?b=1&amp;c=2",
            "HTTP:&#x2f;&#x2f;example.test",
            "#r-1",
            "https:&#x2f;&#x2f;example.test&#x2f;p.png",
        ]
    );
    let made: BTreeSet<String> = WRITER_ELEMENTS
        .iter()
        .map(|&name| name.to_owned())
        .collect();
    assert_eq!(elements(html), made);
    for tag in tags(html) {
        assert!(!handler(tag) && !tag.contains("style"), "{tag}");
    }
    assert!(handler("<div onclick=\"x\">") && !handler("<p title=\"a onclick=b\">"));
}

/// ´test:crate:a-fence-left-open-by-the-cut-closes-at-the-block-end´
#[test]
fn a_fence_left_open_by_the_cut_closes_at_the_block_end() {
    let text = "Intro\n\n```\nlet a = 1;\nlet b = 2;\n```\n";
    let cut = Rendered::cut(text, 20);
    assert_eq!(cut.omitted, text.len() - 20);
    let html = cut.html.as_str();
    assert!(
        html.starts_with("<p>Intro</p>\n<pre><code>let a = 1"),
        "{html}"
    );
    assert!(html.ends_with("</code></pre>\n"), "{html}");
    assert!(!html.contains("let b"), "{html}");
    assert_eq!(cut.lead, "Intro");
}

/// ´test:crate:the-summary-line-is-the-plain-text-of-the-first-block´
#[test]
fn the_summary_line_is_the_plain_text_of_the_first_block() {
    for (text, lead) in [
        ("## **Bold** `code` heading\n\nMore.", "Bold code heading"),
        (
            "\n\n---\n\nAfter *the* rule.\nSame paragraph.",
            "After the rule. Same paragraph.",
        ),
        ("| A | B |\n|---|---|\n| 1 | 2 |", "A · B"),
        (
            "- first [item](https://example.test)\n- second",
            "first item",
        ),
        ("```\ncode line\nsecond\n```", "code line\nsecond\n"),
        ("<div>raw</div>\n\nNext.", "<div>raw</div>\n"),
    ] {
        assert_eq!(first_block(text), lead, "{text}");
    }
}

/// ´test:crate:markup-is-the-one-value-printed-unescaped´
#[test]
fn markup_is_the_one_value_printed_unescaped() {
    let markup = render("*a* <b>");
    let rendered = templates::environment()
        .render_str(
            "{{ markup }}|{{ text }}",
            minijinja::context! { markup => &markup, text => markup.as_str() },
        )
        .expect("render");
    assert_eq!(
        rendered,
        "<p><em>a</em> &lt;b&gt;</p>\n|&lt;p&gt;&lt;em&gt;a&lt;&#x2f;em&gt; &amp;lt;b&amp;gt;&lt;&#x2f;p&gt;\n"
    );
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut makers: Vec<String> = Vec::new();
    for entry in fs::read_dir(sources).expect("sources") {
        let path = entry.expect("entry").path();
        if path.is_file()
            && fs::read_to_string(&path)
                .expect("source")
                .contains("from_safe_string")
        {
            makers.extend(
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
            );
        }
    }
    assert_eq!(makers, ["markdown.rs"]);
    assert!(TEMPLATES.iter().all(|(_, source)| !source.contains("safe")));
}

/// ´test:crate:no-output-file-holds-an-element-outside-the-writer-and-the-templates´
#[test]
fn no_output_file_holds_an_element_outside_the_writer_and_the_templates() {
    let known: BTreeSet<String> = WRITER_ELEMENTS
        .iter()
        .chain(&TEMPLATE_ELEMENTS)
        .map(|&name| name.to_owned())
        .collect();
    for fixture in [
        "-home-alpha-dev-gamma",
        "-home-alpha-dev-hostile",
        "-home-alpha-dev-alpha",
    ] {
        let root = tempfile::tempdir().expect("temporary directory");
        let output = root.path().join("out");
        render_loop(&fixture_projects().join(fixture), &output, 16_384);
        for (name, html) in html_files(&output) {
            let found = elements(&html);
            assert!(found.is_subset(&known), "{fixture} {name}: {found:?}");
            for tag in tags(&html) {
                assert!(!handler(tag), "{fixture} {name}: {tag}");
            }
            assert!(
                hrefs(&html)
                    .iter()
                    .all(|href| !href.contains(':') || href.starts_with("http")),
                "{fixture} {name}"
            );
        }
    }
}

/// ´test:crate:the-hostile-fixture-stays-escaped-with-markdown-on´
#[test]
fn the_hostile_fixture_stays_escaped_with_markdown_on() {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("out");
    render_loop(
        &fixture_projects().join("-home-alpha-dev-hostile"),
        &output,
        16_384,
    );
    let files = html_files(&output);
    let all: String = files.values().cloned().collect();
    let markdown: Vec<&str> = all
        .split("<div class=\"markdown\">")
        .skip(1)
        .filter_map(|rest| rest.split_once("</div>").map(|(inside, _)| inside))
        .collect();
    assert!(
        markdown
            .iter()
            .any(|inside| inside.contains("alert(&quot;response&quot;)"))
    );
    assert!(
        markdown
            .iter()
            .any(|inside| inside.contains("alert(&quot;summary&quot;)"))
    );
    for inside in markdown {
        assert!(
            !inside.contains("<script") && !inside.contains("<img"),
            "{inside}"
        );
    }
    assert!(!all.contains("<script>alert") && !all.contains("<img"));
}
