use std::fmt::Write as _;

pub enum Listing {
    Empty,
    Unread(String),
    History(String),
    Failed(String),
}

impl Listing {
    #[must_use]
    pub fn feedback(&self, limit: usize) -> String {
        let text = match self {
            Self::Empty => "",
            Self::Unread(text) | Self::History(text) | Self::Failed(text) => text,
        };
        let lines = text.lines().collect::<Vec<_>>();
        if lines.len() <= limit {
            return text.to_owned();
        }
        let mut result = lines[..limit - 1].join("\n");
        let _written = write!(
            result,
            "\nMORE ENTRIES n={}; use letters list for the full listing",
            lines.len() - (limit - 1)
        );
        result
    }
}
