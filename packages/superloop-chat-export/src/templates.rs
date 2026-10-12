//! The template environment the pages render through.
//!
//! Every template escapes its values for HTML whatever its name, and the
//! environment removes the `safe` filter, which minijinja keeps in its core
//! even without its builtin filters, so no template can mark transcript text
//! as already escaped.

use minijinja::{AutoEscape, Environment};

use crate::folder::{Fields, hex};

/// The templates compiled into the binary, by name.
pub const TEMPLATES: [(&str, &str); 12] = [
    ("base.html", include_str!("../templates/base.html")),
    ("macros.html", include_str!("../templates/macros.html")),
    ("turns.html", include_str!("../templates/turns.html")),
    ("prompts.html", include_str!("../templates/prompts.html")),
    ("page.html", include_str!("../templates/page.html")),
    ("branch.html", include_str!("../templates/branch.html")),
    ("agent.html", include_str!("../templates/agent.html")),
    ("index.html", include_str!("../templates/index.html")),
    ("rows.html", include_str!("../templates/rows.html")),
    ("pages.html", include_str!("../templates/pages.html")),
    ("loops.html", include_str!("../templates/loops.html")),
    ("latest.html", include_str!("../templates/latest.html")),
];

/// The stylesheet each loop directory carries.
pub const STYLESHEET: &str = include_str!("../assets/chat-export.css");

/// The script each loop directory carries.
pub const SCRIPT: &str = include_str!("../assets/chat-export.js");

/// A template environment that escapes every value for HTML and has no `safe`
/// filter.
#[must_use]
pub fn environment() -> Environment<'static> {
    let mut environment = Environment::new();
    environment.set_auto_escape_callback(|_| AutoEscape::Html);
    environment.remove_filter("safe");
    environment
}

/// The escaping environment with every page template added.
///
/// # Errors
///
/// Returns the error of a template that does not compile.
pub fn with_templates() -> Result<Environment<'static>, minijinja::Error> {
    let mut environment = environment();
    for (name, source) in TEMPLATES {
        environment.add_template(name, source)?;
    }
    Ok(environment)
}

/// The SHA-256 digest, as hex, of every template's name and source in order
/// and of the stylesheet and the script, so a change to any of them renders
/// every page again.
#[must_use]
pub fn digest() -> String {
    let mut digest = Fields::new("superloop-chat-export templates");
    digest.count(TEMPLATES.len());
    for (name, source) in TEMPLATES {
        digest.field(name.as_bytes());
        digest.field(source.as_bytes());
    }
    digest.field(STYLESHEET.as_bytes());
    digest.field(SCRIPT.as_bytes());
    hex(&digest.finish())
}
