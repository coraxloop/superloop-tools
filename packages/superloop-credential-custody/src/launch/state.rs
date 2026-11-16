//! Private case-state core. Later adapters supply observations, never inferred success.
use super::{Result, require};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Phase {
    Reserved,
    SealersStarted,
    Submitted,
    Captured,
    InventoryComplete,
    ReleaseIntent,
    Released,
    GeneratorRetained,
    HolderReleased,
    EofAndSealersComplete,
    SealedSynced,
    Complete,
    Failed,
    Uncertain,
}
#[derive(Debug)]
pub(super) struct State {
    phase: Phase,
    sequence: u32,
}
impl Default for State {
    fn default() -> Self {
        Self {
            phase: Phase::Reserved,
            sequence: 0,
        }
    }
}
impl State {
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }
    pub fn next(&self, next: Phase) -> Result<u32> {
        use Phase::{
            Captured, Complete, EofAndSealersComplete, Failed, GeneratorRetained, HolderReleased,
            InventoryComplete, ReleaseIntent, Released, Reserved, SealedSynced, SealersStarted,
            Submitted, Uncertain,
        };
        require(
            !matches!(self.phase, Complete | Failed | Uncertain),
            "launch-terminal-state",
        )?;
        let expected = match self.phase {
            Reserved => SealersStarted,
            SealersStarted => Submitted,
            Submitted => Captured,
            Captured => InventoryComplete,
            InventoryComplete => ReleaseIntent,
            ReleaseIntent => Released,
            Released => GeneratorRetained,
            GeneratorRetained => HolderReleased,
            HolderReleased => EofAndSealersComplete,
            EofAndSealersComplete => SealedSynced,
            SealedSynced => Complete,
            Complete | Failed | Uncertain => next,
        };
        require(
            next == expected || matches!(next, Failed | Uncertain),
            "launch-state-order",
        )?;
        // At most eleven successful transitions and one terminal failure.
        Ok(self.sequence + 1)
    }
    pub fn commit(&mut self, phase: Phase) -> Result<()> {
        self.sequence = self.next(phase)?;
        self.phase = phase;
        Ok(())
    }
    pub const fn publication_failed(&mut self) {
        self.phase = Phase::Uncertain;
    }
}
