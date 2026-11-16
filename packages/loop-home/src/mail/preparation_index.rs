//! Rebuildable writer-owned lookups, never delivery provenance.
use super::journal::{MailError, Record, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;

type Source = (String, String);
pub(super) struct Index {
    incomplete: HashMap<Source, HashSet<String>>,
    paths: HashMap<String, u64>,
    serial: Option<u128>,
}
impl Default for Index {
    fn default() -> Self {
        Self {
            incomplete: HashMap::new(),
            paths: HashMap::new(),
            serial: Some(0),
        }
    }
}
impl Index {
    pub fn record(&mut self, record: &Record, new: bool) {
        let key = (record.sender.clone(), record.outgoing.clone());
        let delivery = record.delivery.to_string();
        if record.completed.is_none() {
            self.incomplete.entry(key).or_default().insert(delivery);
        } else if let Some(deliveries) = self.incomplete.get_mut(&key) {
            deliveries.remove(&delivery);
            if deliveries.is_empty() {
                self.incomplete.remove(&key);
            }
        }
        if new {
            self.reserve_paths(record);
        }
    }
    pub fn reserve_paths(&mut self, record: &Record) {
        for path in paths(record) {
            *self.paths.entry(path.to_owned()).or_default() += 1;
            let serial = Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| {
                    name.strip_prefix("payload-")
                        .or_else(|| name.strip_prefix("copy-"))
                })
                .and_then(|serial| serial.parse::<u128>().ok());
            if let Some(serial) = serial {
                self.serial = self
                    .serial
                    .and_then(|current| serial.checked_add(1).map(|next| current.max(next)));
            }
        }
    }
    pub fn remove(&mut self, record: &Record) {
        let key = (record.sender.clone(), record.outgoing.clone());
        if let Some(deliveries) = self.incomplete.get_mut(&key) {
            deliveries.remove(&record.delivery.to_string());
            if deliveries.is_empty() {
                self.incomplete.remove(&key);
            }
        }
        for path in paths(record) {
            if let Some(count) = self.paths.get_mut(path) {
                *count -= 1;
                if *count == 0 {
                    self.paths.remove(path);
                }
            }
        }
    }
    pub fn pending(&self, sender: &str, outgoing: &str) -> bool {
        self.incomplete
            .contains_key(&(sender.to_owned(), outgoing.to_owned()))
    }
    pub fn reserved(&self, path: &Path) -> Result<bool> {
        Ok(self.paths.contains_key(
            path.to_str()
                .ok_or(MailError::Invalid("staging path encoding"))?,
        ))
    }
    pub fn next_serial(&mut self) -> Result<u128> {
        let serial = self.serial.ok_or(MailError::Capacity)?;
        self.serial = serial.checked_add(1);
        Ok(serial)
    }
}
fn paths(record: &Record) -> impl Iterator<Item = &str> {
    std::iter::once(record.recipient_temporary.path.as_str()).chain(
        record
            .sender_temporary
            .iter()
            .map(|temporary| temporary.path.as_str()),
    )
}
