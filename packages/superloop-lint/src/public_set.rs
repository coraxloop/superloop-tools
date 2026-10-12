//! Publication classification applies only to repositories declaring a manifest.

use std::path::Path;

use crate::finding::{Finding, Location};
use superloop_cli_common::public_set::{Manifest, Selection, tracked_paths};

pub fn check(root: &Path) -> (Option<Selection>, Vec<Finding>) {
    let path = root.join("public-set.toml");
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return (
                None,
                vec![finding("manifest must be a regular file".into())],
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return (None, Vec::new()),
        Err(error) => return (None, vec![finding(error.to_string())]),
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => return (None, vec![finding(error.to_string())]),
    };
    let result = Manifest::parse(&text)
        .and_then(|manifest| tracked_paths(root).map(|paths| manifest.select(&paths)));
    match result {
        Ok(selection) => {
            let findings = selection.issues.iter().cloned().map(finding).collect();
            (Some(selection), findings)
        }
        Err(error) => (None, vec![finding(error)]),
    }
}

fn finding(detail: String) -> Finding {
    Finding::PublicSet {
        detail,
        location: Location::new("public-set.toml", "", 0),
    }
}
