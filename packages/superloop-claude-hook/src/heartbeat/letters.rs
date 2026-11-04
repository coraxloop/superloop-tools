use std::env;
use std::path::Path;

use loop_home::{load_registry, registry_path};

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
    let output = match entry_listing::run(home, &row.name, &row.home.join("mail/inbox")) {
        Ok(output) => output,
        Err(reason) => return (Some(row.name.clone()), failed(&reason)),
    };
    (Some(row.name.clone()), listing(&row.name, &output.stdout))
}

/// Interpret only the fixed presence marker emitted by the ordinary shell test.
#[must_use]
pub fn listing(_loop_name: &str, bytes: &[u8]) -> Listing {
    match bytes {
        b"" => Listing::Empty,
        b"1\n" => Listing::Notice,
        b"unavailable\n" => failed("mail inbox is missing or unreadable"),
        _ => failed("unexpected inbox presence result"),
    }
}
