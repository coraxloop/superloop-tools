//! Byte escaping and UTC decoding for driver observations.

/// Escape every byte outside the small safe field alphabet, preserving exact names.
#[must_use]
pub fn escape_name(name: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut escaped = String::new();
    for &byte in name {
        if byte.is_ascii_alphanumeric() || b"._-".contains(&byte) {
            escaped.push(char::from(byte));
        } else {
            escaped.push('%');
            escaped.push(char::from(HEX[usize::from(byte >> 4)]));
            escaped.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    escaped
}

/// Parse a UTC instant, accepting Z or +00:00 and an optional decimal fraction.
/// Returns None for malformed instants or dates outside 1970 through 9999.
#[must_use]
pub fn parse_utc_instant(value: &str) -> Option<u64> {
    if !value.is_ascii() {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let suffix = &value[19..];
    let fraction = suffix.strip_prefix('.');
    let zone = if let Some(fraction) = fraction {
        let end = fraction.find(|ch: char| !ch.is_ascii_digit())?;
        if end == 0 {
            return None;
        }
        &fraction[end..]
    } else {
        suffix
    };
    if zone != "Z" && zone != "+00:00" {
        return None;
    }
    let year = instant_decimal(&value[..4])?;
    let month = instant_decimal(&value[5..7])?;
    let day = instant_decimal(&value[8..10])?;
    let hour = instant_decimal(&value[11..13])?;
    let minute = instant_decimal(&value[14..16])?;
    let second = instant_decimal(&value[17..19])?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        28 + u64::from(leap),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let index = usize::try_from(month - 1).ok()?;
    if day == 0 || day > month_days[index] {
        return None;
    }
    let prior_months: u64 = month_days[..index].iter().sum();
    let days = days_before_year(year) - days_before_year(1970) + prior_months + day - 1;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

const fn days_before_year(year: u64) -> u64 {
    let last = year - 1;
    last * 365 + last / 4 - last / 100 + last / 400
}

fn instant_decimal(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())?
}
