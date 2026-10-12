use std::env;
use std::fmt::Write as _;
use std::path::Path;

use loop_home::{load_registry, parse_letter_metadata, registry_path};

use super::entry_listing;
use super::project_root::project_root;

pub use session_core::letters::Listing;

fn failed(reason: &str) -> Listing {
    let mut text = format!(
        "LETTERS listing failed reason=\"{}\"",
        reason.escape_debug()
    );
    if text.len() > 4096 {
        let mut end = 4093;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
    }
    Listing::Failed(text)
}

#[must_use]
pub fn inspect(cwd: &str, home: &Path) -> (Option<String>, Listing) {
    let root = project_root(Path::new(cwd), Some(home));
    let Ok(registry) = load_registry(&registry_path(
        env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        home,
    )) else {
        return (None, Listing::Empty);
    };
    let rows = registry.rows(home);
    let mut matching = rows
        .iter()
        .filter(|row| project_root(&row.launch, Some(home)) == root);
    let Some(row) = matching.next() else {
        return (None, Listing::Empty);
    };
    if matching.next().is_some() {
        return (
            None,
            failed(&format!("ambiguous loop for cwd: {}", root.display())),
        );
    }
    let output = match entry_listing::run(home, &row.name) {
        Ok(output) => output,
        Err(reason) => return (Some(row.name.clone()), failed(&reason)),
    };
    (Some(row.name.clone()), listing(&row.name, &output.stdout))
}

#[must_use]
pub fn listing(loop_name: &str, bytes: &[u8]) -> Listing {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return failed("malformed listing output: invalid UTF-8");
    };
    let mut entries = Vec::new();
    let mut refused = 0usize;
    for line in text.lines() {
        if line
            .split_once(' ')
            .is_some_and(|(_, rest)| rest.starts_with("refused reason="))
        {
            refused = refused.saturating_add(1);
            continue;
        }
        let Ok(entry) = parse_letter_metadata(line) else {
            return failed("malformed listing output: expected five letter fields");
        };
        entries.push(entry);
    }
    if entries.is_empty() && refused == 0 {
        return Listing::Empty;
    }
    entries.sort_by(|a, b| (b.posted_ns, &b.name).cmp(&(a.posted_ns, &a.name)));
    let unread = entries.iter().filter(|entry| entry.unread).count();
    let mut feedback = format!("LETTERS unread={unread} loop={loop_name}");
    if refused > 0 {
        let _written = write!(feedback, " refused={refused}");
    }
    if feedback.len() > 4096 - 80 {
        return failed("loop identity exceeds feedback budget");
    }
    let mut displayed = 0;
    for entry in entries.iter().take(8) {
        let line = format!(
            "\n{} sender={} posted_ns={} unread={}",
            entry.name, entry.sender, entry.posted_ns, entry.unread
        );
        // Reserve the complete omission line before adding an entry.
        if feedback.len() + line.len() + 80 > 4096 {
            break;
        }
        feedback.push_str(&line);
        displayed += 1;
    }
    if displayed < entries.len() {
        let _written = write!(
            feedback,
            "\nMORE ENTRIES n={}; use letters list for the full listing",
            entries.len() - displayed
        );
    }
    if unread > 0 {
        Listing::Unread(feedback)
    } else {
        Listing::History(feedback)
    }
}
