//! Calendar-valid, lexically ordered UTC milliseconds from ``lang:mail:names``.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::journal::{MailError, Result};

/// A representable UTC delivery instant. Deserialization revalidates the calendar.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Instant(String);

const fn leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn month_days(year: u32, month: u32) -> u32 {
    match month {
        2 => {
            if leap(year) {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl Instant {
    /// Parse exactly the specified spelling and Gregorian UTC calendar.
    ///
    /// # Errors
    /// Refuses invalid dates, leap seconds and years outside 0001 through 9999.
    pub fn parse(value: &str) -> Result<Self> {
        let bytes = value.as_bytes();
        if bytes.len() != 24
            || bytes.iter().enumerate().any(|(index, byte)| match index {
                4 | 7 => *byte != b'-',
                10 => *byte != b'T',
                13 | 16 => *byte != b':',
                19 => *byte != b'.',
                23 => *byte != b'Z',
                _ => !byte.is_ascii_digit(),
            })
        {
            return Err(MailError::Invalid("delivery instant"));
        }
        let number = |start: usize, end: usize| -> Result<u32> {
            value[start..end]
                .parse()
                .map_err(|_| MailError::Invalid("delivery instant"))
        };
        let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
        if year == 0
            || !(1..=12).contains(&month)
            || day == 0
            || day > month_days(year, month)
            || number(11, 13)? > 23
            || number(14, 16)? > 59
            || number(17, 19)? > 59
        {
            return Err(MailError::Invalid("delivery calendar"));
        }
        Ok(Self(value.to_owned()))
    }

    /// Read the actual host clock; callers wait rather than inventing later instants.
    ///
    /// # Errors
    /// Refuses unavailable or unrepresentable host time.
    pub fn now() -> Result<Self> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MailError::Invalid("UTC clock before epoch"))?;
        let mut days = elapsed.as_secs() / 86_400;
        let mut year = 1970;
        loop {
            let length = if leap(year) { 366 } else { 365 };
            if days < length {
                break;
            }
            days -= length;
            year += 1;
            if year > 9999 {
                return Err(MailError::Invalid("UTC year exhausted"));
            }
        }
        let mut month = 1;
        while days >= u64::from(month_days(year, month)) {
            days -= u64::from(month_days(year, month));
            month += 1;
        }
        let seconds = elapsed.as_secs() % 86_400;
        Self::parse(&format!(
            "{year:04}-{month:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            days + 1,
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60,
            elapsed.subsec_millis()
        ))
    }

    /// Elapsed milliseconds from the beginning of the Gregorian year 0001.
    #[must_use]
    pub fn millis(&self) -> u64 {
        // Construction and deserialization check every field.
        let n = |start: usize, end: usize| {
            self.0[start..end]
                .bytes()
                .fold(0u32, |value, byte| value * 10 + u32::from(byte - b'0'))
        };
        let (year, month) = (n(0, 4), n(5, 7));
        let before = u64::from(year - 1);
        let days = before * 365 + before / 4 - before / 100
            + before / 400
            + (1..month)
                .map(|m| u64::from(month_days(year, m)))
                .sum::<u64>()
            + u64::from(n(8, 10) - 1);
        ((days * 24 + u64::from(n(11, 13))) * 3600
            + u64::from(n(14, 16)) * 60
            + u64::from(n(17, 19)))
            * 1000
            + u64::from(n(20, 23))
    }
}

impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl TryFrom<String> for Instant {
    type Error = MailError;
    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}
impl From<Instant> for String {
    fn from(value: Instant) -> Self {
        value.0
    }
}
