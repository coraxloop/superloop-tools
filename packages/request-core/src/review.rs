use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub review_id: String,
    pub at: String,
    pub at_ns: u64,
}

/// Read the clock in nanoseconds since the Unix epoch.
///
/// # Errors
/// Refuses a pre-epoch or unrepresentable clock reading.
pub fn now_ns() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| duration.as_nanos().try_into().ok())
        .ok_or_else(|| Error::new("requests-clock", "clock cannot represent UTC nanoseconds"))
}

/// Render an epoch nanosecond reading in the fixed UTC review representation.
#[must_use]
pub fn utc_time(ns: u64) -> String {
    let seconds = ns / 1_000_000_000;
    let (year, month, day) = civil_date(seconds / 86_400);
    let day_seconds = seconds % 86_400;
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:09}Z",
        ns % 1_000_000_000
    )
}

fn civil_date(days_since_epoch: u64) -> (u64, u64, u64) {
    let days = days_since_epoch + 719_468;
    let era = days / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    year += u64::from(month <= 2);
    (year, month, day)
}

fn identifier(id: &str, at: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"superloop-review-v1\0");
    hash.update(id.as_bytes());
    hash.update(b"\0");
    hash.update(at.as_bytes());
    let bytes = hash.finalize();
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

pub fn next(id: &str, now: u64, history: &[Review]) -> Result<Review, Error> {
    next_with(id, now, history, identifier)
}

fn next_with(
    id: &str,
    now: u64,
    history: &[Review],
    hash: impl Fn(&str, &str) -> String,
) -> Result<Review, Error> {
    let used: BTreeSet<_> = history
        .iter()
        .map(|review| review.review_id.as_str())
        .collect();
    if u64::try_from(used.len()).unwrap_or(u64::MAX) >= 1_u64 << 32 {
        return Err(Error::new("requests-review-exhausted", id));
    }
    let mut at_ns = match history.last() {
        Some(previous) => now.max(
            previous
                .at_ns
                .checked_add(1)
                .ok_or_else(|| Error::new("requests-clock", id))?,
        ),
        None => now,
    };
    loop {
        let at = utc_time(at_ns);
        let review_id = hash(id, &at);
        if !used.contains(review_id.as_str()) {
            return Ok(Review {
                review_id,
                at,
                at_ns,
            });
        }
        at_ns = at_ns
            .checked_add(1)
            .ok_or_else(|| Error::new("requests-clock", id))?;
    }
}

pub fn valid(id: &str, history: &[Review]) -> bool {
    let mut seen = BTreeSet::new();
    history.iter().all(|review| {
        crate::hex(&review.review_id, 8)
            && review.at == utc_time(review.at_ns)
            && review.review_id == identifier(id, &review.at)
            && seen.insert(&review.review_id)
    }) && history.windows(2).all(|pair| pair[0].at_ns < pair[1].at_ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:review-identifier-pins-domain-separators-and-canonical-utc-bytes´
    #[test]
    fn review_identifier_pins_domain_separators_and_canonical_utc_bytes() {
        let review = next(&"0".repeat(64), 100, &[]).expect("review");
        assert_eq!(review.at, "1970-01-01T00:00:00.000000100Z");
        assert_eq!(review.review_id, "3674b2dc");
        assert_eq!(
            utc_time(1_700_000_000_123_456_789),
            "2023-11-14T22:13:20.123456789Z"
        );
    }

    /// ´test:unit:review-collision-advances-time-without-reusing-an-identifier´
    #[test]
    fn review_collision_advances_time_without_reusing_an_identifier() {
        let history = [Review {
            review_id: "00000000".to_owned(),
            at: utc_time(1),
            at_ns: 1,
        }];
        let review = next_with(&"a".repeat(64), 1, &history, |_, at| {
            if at == utc_time(2) {
                "00000000"
            } else {
                "00000001"
            }
            .to_owned()
        })
        .expect("collision advances");
        assert_eq!(review.at_ns, 3);
        assert_eq!(review.review_id, "00000001");
    }
}
