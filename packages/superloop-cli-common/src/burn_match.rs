//! Literal burn matching shared by the census and unpublished-label guard.

/// Return non-overlapping, case-sensitive byte offsets of a declared value.
///
/// Identifier mode requires ends or non-ASCII-letter bytes on both sides,
/// matching the external burn census convention. Empty values never match.
pub fn burn_offsets<'a>(
    source: &'a [u8],
    needle: &'a [u8],
    identifier: bool,
) -> impl Iterator<Item = usize> + 'a {
    let mut cursor = 0;
    std::iter::from_fn(move || {
        if needle.is_empty() {
            return None;
        }
        while cursor + needle.len() <= source.len() {
            let relative = source[cursor..]
                .windows(needle.len())
                .position(|window| window == needle)?;
            let offset = cursor + relative;
            cursor = offset + needle.len();
            if !identifier
                || (source
                    .get(offset.wrapping_sub(1))
                    .is_none_or(|byte| !byte.is_ascii_alphabetic())
                    && source
                        .get(cursor)
                        .is_none_or(|byte| !byte.is_ascii_alphabetic()))
            {
                return Some(offset);
            }
        }
        None
    })
}
