//! Unselected launcher cores. No installed entrypoint or plaintext reader.
mod campaign;
mod channel;
mod child_status;
mod confinement;
mod control;
mod fifo;
mod handoff;
mod inventory;
mod keeper;
use keeper::manager;
mod measure;
mod policy;
mod process_pin;
mod sealer;
mod startup;
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

#[cfg(test)]
mod test_support;
