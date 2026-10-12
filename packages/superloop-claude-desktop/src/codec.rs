use std::collections::BTreeMap;
use std::io;

pub type Values = BTreeMap<Vec<u8>, (u64, Option<Vec<u8>>)>;
type Entries = Vec<(Vec<u8>, Vec<u8>)>;
pub const BLOCK: usize = 32768;
const LIMIT: usize = 64 * 1024 * 1024;

fn bad() -> io::Error {
    io::Error::other("malformed LevelDB record")
}

pub fn crc(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 == 1 { 0x82f6_3b78 } else { 0 };
        }
    }
    !crc
}

pub const fn mask(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> io::Result<&'a [u8]> {
    let (head, rest) = bytes.split_at_checked(count).ok_or_else(bad)?;
    *bytes = rest;
    Ok(head)
}

fn u32le(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| bad())?))
}
fn u64le(bytes: &[u8]) -> io::Result<u64> {
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| bad())?))
}

fn varint(bytes: &mut &[u8]) -> io::Result<u64> {
    let mut value = 0;
    for shift in (0..=63).step_by(7) {
        let byte = take(bytes, 1)?[0];
        if shift == 63 && byte > 1 {
            return Err(bad());
        }
        value |= u64::from(byte & 127) << shift;
        if byte < 128 {
            return Ok(value);
        }
    }
    Err(bad())
}

fn length(bytes: &mut &[u8]) -> io::Result<usize> {
    let size = usize::try_from(varint(bytes)?).map_err(|_| bad())?;
    if size > LIMIT {
        return Err(bad());
    }
    Ok(size)
}

fn putvar(mut number: u64, out: &mut Vec<u8>) {
    while number >= 128 {
        out.push(u8::try_from(number & 127).unwrap_or(0) | 128);
        number >>= 7;
    }
    out.push(u8::try_from(number).unwrap_or(0));
}

fn batch(mut bytes: &[u8], values: &mut Values) -> io::Result<u64> {
    let sequence = u64le(take(&mut bytes, 8)?)?;
    let count = u32le(take(&mut bytes, 4)?)?;
    for index in 0..count {
        let kind = take(&mut bytes, 1)?[0];
        let size = length(&mut bytes)?;
        let key = take(&mut bytes, size)?.to_vec();
        let value = match kind {
            0 => None,
            1 => {
                let size = length(&mut bytes)?;
                Some(take(&mut bytes, size)?.to_vec())
            }
            _ => return Err(bad()),
        };
        let seq = sequence.checked_add(u64::from(index)).ok_or_else(bad)?;
        if values.get(&key).is_none_or(|(old, _)| *old < seq) {
            values.insert(key, (seq, value));
        }
    }
    if !bytes.is_empty() {
        return Err(bad());
    }
    if count == 0 {
        return Ok(sequence.saturating_sub(1));
    }
    sequence.checked_add(u64::from(count - 1)).ok_or_else(bad)
}

pub fn log(data: &[u8]) -> io::Result<(Values, u64)> {
    let mut position = 0;
    let mut fragment: Option<Vec<u8>> = None;
    let mut values = Values::new();
    let mut maximum = 0;
    while position < data.len() {
        let left = BLOCK - position % BLOCK;
        if left < 7 {
            position += left;
            continue;
        }
        let header = data.get(position..position + 7).ok_or_else(bad)?;
        let size = usize::from(u16::from_le_bytes([header[4], header[5]]));
        let kind = header[6];
        if kind == 0 && size == 0 {
            position += left;
            continue;
        }
        if size + 7 > left {
            return Err(bad());
        }
        let payload = data
            .get(position + 7..position + 7 + size)
            .ok_or_else(bad)?;
        let mut checksum = vec![kind];
        checksum.extend_from_slice(payload);
        if mask(crc(&checksum)) != u32le(&header[..4])? {
            return Err(io::Error::other("LevelDB checksum mismatch"));
        }
        position += 7 + size;
        match kind {
            1 if fragment.is_none() => maximum = maximum.max(batch(payload, &mut values)?),
            2 if fragment.is_none() => fragment = Some(payload.to_vec()),
            3 | 4 => {
                let mut part = fragment.take().ok_or_else(bad)?;
                if part.len().saturating_add(payload.len()) > LIMIT {
                    return Err(bad());
                }
                part.extend_from_slice(payload);
                if kind == 4 {
                    maximum = maximum.max(batch(&part, &mut values)?);
                } else {
                    fragment = Some(part);
                }
            }
            _ => return Err(bad()),
        }
    }
    if fragment.is_some() {
        return Err(bad());
    }
    Ok((values, maximum))
}

pub fn append(sequence: u64, entries: &[(Vec<u8>, Vec<u8>)], offset: usize) -> io::Result<Vec<u8>> {
    let mut payload = sequence.to_le_bytes().to_vec();
    payload.extend_from_slice(
        &u32::try_from(entries.len())
            .map_err(|_| bad())?
            .to_le_bytes(),
    );
    for (key, value) in entries {
        payload.push(1);
        putvar(u64::try_from(key.len()).map_err(|_| bad())?, &mut payload);
        payload.extend_from_slice(key);
        putvar(u64::try_from(value.len()).map_err(|_| bad())?, &mut payload);
        payload.extend_from_slice(value);
    }
    let mut result = Vec::new();
    let mut bytes = payload.as_slice();
    let mut first = true;
    while !bytes.is_empty() {
        let mut left = BLOCK - (offset + result.len()) % BLOCK;
        if left < 7 {
            result.resize(result.len() + left, 0);
            left = BLOCK;
        }
        let size = bytes.len().min(left - 7);
        let part = take(&mut bytes, size)?;
        let kind = match (first, bytes.is_empty()) {
            (true, true) => 1,
            (true, false) => 2,
            (false, true) => 4,
            (false, false) => 3,
        };
        let mut checksum = vec![kind];
        checksum.extend_from_slice(part);
        result.extend_from_slice(&mask(crc(&checksum)).to_le_bytes());
        result.extend_from_slice(&u16::try_from(size).map_err(|_| bad())?.to_le_bytes());
        result.push(kind);
        result.extend_from_slice(part);
        first = false;
    }
    Ok(result)
}

fn snappy(mut source: &[u8]) -> io::Result<Vec<u8>> {
    let expected = length(&mut source)?;
    let mut out = Vec::with_capacity(expected);
    while !source.is_empty() {
        let tag = take(&mut source, 1)?[0];
        let kind = tag & 3;
        if kind == 0 {
            let mut size = usize::from(tag >> 2) + 1;
            if size > 60 {
                let mut raw = [0; 4];
                let count = size - 60;
                raw[..count].copy_from_slice(take(&mut source, count)?);
                size = usize::try_from(u32::from_le_bytes(raw))
                    .map_err(|_| bad())?
                    .checked_add(1)
                    .ok_or_else(bad)?;
            }
            if out.len().saturating_add(size) > expected {
                return Err(bad());
            }
            out.extend_from_slice(take(&mut source, size)?);
        } else {
            let (size, distance) = match kind {
                1 => (
                    usize::from((tag >> 2) & 7) + 4,
                    (usize::from(tag >> 5) << 8) | usize::from(take(&mut source, 1)?[0]),
                ),
                2 => (
                    usize::from(tag >> 2) + 1,
                    usize::from(u16::from_le_bytes(
                        take(&mut source, 2)?.try_into().map_err(|_| bad())?,
                    )),
                ),
                _ => (
                    usize::from(tag >> 2) + 1,
                    usize::try_from(u32le(take(&mut source, 4)?)?).map_err(|_| bad())?,
                ),
            };
            if distance == 0 || distance > out.len() || out.len().saturating_add(size) > expected {
                return Err(bad());
            }
            for _ in 0..size {
                out.push(out[out.len() - distance]);
            }
        }
    }
    if out.len() != expected {
        return Err(bad());
    }
    Ok(out)
}

fn table_block(file: &[u8], mut handle: &[u8]) -> io::Result<Entries> {
    let offset = length(&mut handle)?;
    let size = length(&mut handle)?;
    let raw = file
        .get(offset..offset.checked_add(size).ok_or_else(bad)?)
        .ok_or_else(bad)?;
    let trailer = file.get(offset + size..offset + size + 5).ok_or_else(bad)?;
    let mut checksum = raw.to_vec();
    checksum.push(trailer[0]);
    if mask(crc(&checksum)) != u32le(&trailer[1..])? {
        return Err(io::Error::other("LevelDB table checksum mismatch"));
    }
    let decoded = match trailer[0] {
        0 => raw.to_vec(),
        1 => snappy(raw)?,
        _ => return Err(bad()),
    };
    let restarts = usize::try_from(u32le(
        decoded
            .get(decoded.len().checked_sub(4).ok_or_else(bad)?..)
            .ok_or_else(bad)?,
    )?)
    .map_err(|_| bad())?;
    let end = decoded
        .len()
        .checked_sub(
            restarts
                .checked_mul(4)
                .and_then(|n| n.checked_add(4))
                .ok_or_else(bad)?,
        )
        .ok_or_else(bad)?;
    let mut bytes = &decoded[..end];
    let mut key = Vec::new();
    let mut entries = Vec::new();
    while !bytes.is_empty() {
        let shared = length(&mut bytes)?;
        let suffix = length(&mut bytes)?;
        let value = length(&mut bytes)?;
        if shared > key.len() {
            return Err(bad());
        }
        key.truncate(shared);
        key.extend_from_slice(take(&mut bytes, suffix)?);
        entries.push((key.clone(), take(&mut bytes, value)?.to_vec()));
    }
    Ok(entries)
}

pub fn table(file: &[u8]) -> io::Result<Values> {
    let footer = file
        .get(file.len().checked_sub(48).ok_or_else(bad)?..)
        .ok_or_else(bad)?;
    if footer[40..] != [0x57, 0xfb, 0x80, 0x8b, 0x24, 0x75, 0x47, 0xdb] {
        return Err(bad());
    }
    let mut handles = &footer[..40];
    varint(&mut handles)?;
    varint(&mut handles)?;
    let mut values = Values::new();
    for (_, handle) in table_block(file, handles)? {
        for (key, value) in table_block(file, &handle)? {
            let split = key.len().checked_sub(8).ok_or_else(bad)?;
            let tag = u64le(&key[split..])?;
            let sequence = tag >> 8;
            let value = match tag & 255 {
                0 => None,
                1 => Some(value),
                _ => return Err(bad()),
            };
            let key = key[..split].to_vec();
            if values.get(&key).is_none_or(|(old, _)| *old < sequence) {
                values.insert(key, (sequence, value));
            }
        }
    }
    Ok(values)
}
