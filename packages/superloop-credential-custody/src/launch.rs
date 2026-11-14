//! Unselected launcher cores. No entrypoint, manager adapter or plaintext reader.
mod channel;
mod confinement;
mod measure;
mod policy;
mod sealer;
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

#[cfg(test)]
mod sealer_tests;
