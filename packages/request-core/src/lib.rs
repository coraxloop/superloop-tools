#![doc = include_str!("../README.md")]

pub mod gateway;
mod model;
mod review;
pub mod transaction;

pub use model::{Collection, Decision, Kind, Request, State};
pub use review::{Review, now_ns, utc_time};

/// A named request refusal, without implicit authority or recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub class: &'static str,
    pub detail: String,
}

impl Error {
    #[must_use]
    pub fn new(class: &'static str, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.class, self.detail)
    }
}

impl std::error::Error for Error {}

pub(crate) fn exact(value: &serde_json::Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

pub(crate) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Hash a caller-owned, stable source identity into the common request ID.
#[must_use]
pub fn request_id(source: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(source) {
        let _written = write!(result, "{byte:02x}");
    }
    result
}
