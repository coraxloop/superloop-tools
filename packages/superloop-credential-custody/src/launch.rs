//! Unselected launcher cores. No entrypoint, manager adapter or plaintext reader.
mod measure;
mod policy;
mod state;
mod store;

use crate::record::Result;

const fn require(condition: bool, class: &'static str) -> Result<()> {
    if !condition {
        return Err(class);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
