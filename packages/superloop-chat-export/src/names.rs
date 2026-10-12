//! The one grammar for every name the program turns into a folder, a file or
//! a link: a loop's name from the registry and each segment it derives from a
//! transcript's file name.
//!
//! A segment is one to 64 bytes of ASCII letters, digits, `-`, `_` and `.`,
//! opening with a letter or a digit. It holds no separator, no parent
//! component, no scheme and nothing a URL would read as a query or a
//! fragment, and every byte of it is unreserved in a URL, so a link built from
//! segments needs no escaping and leaves no folder.

/// The most bytes a segment holds.
pub const SEGMENT_MAX: usize = 64;

/// Whether `text` is a segment of the grammar.
#[must_use]
pub fn is_segment(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=SEGMENT_MAX).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// `text` with every byte outside a URL's unreserved set percent-encoded; a
/// segment comes back unchanged.
#[must_use]
pub fn url_segment(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte >> 4)]));
            encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte & 0xf)]));
        }
    }
    encoded
}

/// The files every run writes into a loop's folder whatever its plan holds.
pub const FIXED_FILES: [&str; 7] = [
    "chat-export.css",
    "chat-export.js",
    "index.html",
    "latest.html",
    "pages.html",
    "chat-export-manifest.json",
    "chat-export-journal.txt",
];

/// Whether `digits` is a run of ASCII digits at least `least` long.
fn digits(text: &str, least: usize) -> bool {
    text.len() >= least && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `name` is a numbered page `STEM-NN.html`: a segment, then at least
/// two digits after the last `-`, so two distinct stems never number a page
/// alike.
fn numbered(name: &str) -> bool {
    name.strip_suffix(".html")
        .and_then(|rest| rest.rsplit_once('-'))
        .is_some_and(|(stem, part)| is_segment(stem) && digits(part, 2))
}

/// Whether `path` is a page name of one conversation's folder: a main page
/// `pNNNN.html`, the page list, or a branch page `branches/STEM-NN.html`.
fn conversation_page(path: &str) -> bool {
    if path == "pages.html" {
        return true;
    }
    if let Some(number) = path
        .strip_prefix('p')
        .and_then(|rest| rest.strip_suffix(".html"))
    {
        return digits(number, 4);
    }
    path.strip_prefix("branches/").is_some_and(numbered)
}

/// Whether `path` is of the grammar of the files the program writes into a
/// loop's folder.
///
/// Those are the fixed files, the pages of the first conversation, a later
/// conversation's pages under `cN/`, and an agent thread's pages
/// `agents/ID-NN.html`.
#[must_use]
pub fn generated(path: &str) -> bool {
    if FIXED_FILES.contains(&path) || conversation_page(path) {
        return true;
    }
    if let Some(name) = path.strip_prefix("agents/") {
        return numbered(name);
    }
    path.strip_prefix('c')
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(number, page)| {
            digits(number, 1)
                && !number.starts_with('0')
                && number != "1"
                && conversation_page(page)
        })
}
