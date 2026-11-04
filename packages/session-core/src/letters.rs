/// Presence-only mail observation. Correspondence metadata is not an observation.
pub enum Listing {
    Empty,
    Notice,
    Failed(String),
}

impl Listing {
    #[must_use]
    pub fn feedback(&self, _limit: usize) -> String {
        match self {
            Self::Empty => String::new(),
            Self::Notice => "You've got mail.".into(),
            Self::Failed(text) => text.clone(),
        }
    }
}
