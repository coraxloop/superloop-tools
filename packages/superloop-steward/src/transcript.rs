use crate::protocol::{self, Position, Positions, Row};
use crate::ssh::{self, Transport};
use std::io::{self, Write as _};
use std::time::{Duration, Instant};

pub trait Runtime {
    fn elapsed(&self) -> Duration;
    fn sleep(&self, duration: Duration);
    fn read(
        &self,
        transport: &Transport,
        alias: &str,
        command: &str,
        timeout: Duration,
    ) -> io::Result<std::process::Output>;
}

pub struct SystemRuntime(Instant);

impl SystemRuntime {
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Runtime for SystemRuntime {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
    fn read(
        &self,
        transport: &Transport,
        alias: &str,
        command: &str,
        timeout: Duration,
    ) -> io::Result<std::process::Output> {
        transport.read(alias, command, timeout)
    }
}

pub struct Reader<'a> {
    pub transport: &'a Transport,
    pub alias: &'a str,
    pub exporter: &'a str,
    pub runtime: &'a dyn Runtime,
    pub start: Duration,
    pub deadline: Duration,
    pub timeout: Duration,
    pub chunk: u64,
    pub tail: u64,
}

pub struct Batch {
    pub positions: Positions,
    pub output: Vec<u8>,
    pub findings: usize,
    pub content: bool,
    pub suppressed: usize,
}

impl Reader<'_> {
    pub fn remote(&self, args: &str) -> io::Result<Vec<u8>> {
        let remaining = self
            .deadline
            .saturating_sub(self.runtime.elapsed().saturating_sub(self.start));
        if remaining.is_zero() {
            return Err(io::Error::other("transcript deadline"));
        }
        let result = self.runtime.read(
            self.transport,
            self.alias,
            &format!("{} {args}", ssh::quote(self.exporter)),
            self.timeout.min(remaining),
        )?;
        if !result.status.success() {
            return Err(io::Error::other(format!(
                "{} server={} status={}",
                args.split_whitespace().next().unwrap_or("read"),
                self.alias.strip_suffix("-steward").unwrap_or(self.alias),
                result.status.code().unwrap_or(1)
            )));
        }
        Ok(result.stdout)
    }

    fn exact(&self, path: &str, offset: u64, count: u64) -> io::Result<Option<Vec<u8>>> {
        let bytes = self.remote(&format!("read {} {offset} {count}", ssh::quote(path)))?;
        Ok((u64::try_from(bytes.len()).ok() == Some(count)).then_some(bytes))
    }

    fn verify(&self, row: &Row, old: &Position) -> io::Result<Option<&'static str>> {
        if old.offset < old.high {
            return Ok(Some("cursor-regression"));
        }
        if row.size < old.offset || row.size < old.observed {
            return Ok(Some("truncation"));
        }
        if old.offset > 0 {
            let Some(tail) = self.exact(&row.path, old.tail_start, old.offset - old.tail_start)?
            else {
                return Ok(Some("rewrite-short-read"));
            };
            if protocol::digest(&tail) != old.tail_hash {
                return Ok(Some("rewrite-tail-mismatch"));
            }
        }
        let unchanged_size = row.size == old.observed;
        if unchanged_size && row.stamp != old.stamp {
            return Ok(Some("rewrite-metadata"));
        }
        Ok(None)
    }

    fn process(&self, server: &str, row: &Row, batch: &mut Batch) -> io::Result<()> {
        let key = (row.path.clone(), row.identity.clone());
        let old = batch.positions.get(&key).cloned();
        if let Some(old) = &old {
            if let Some(kind) = self.verify(row, old)? {
                return batch.finding(server, row, kind);
            }
        } else if batch.positions.keys().any(|(path, _)| path == &row.path) {
            batch.finding(server, row, "replacement")?;
        }
        let offset = old.as_ref().map_or(0, |old| old.offset);
        let mut data = Vec::new();
        let mut position = offset;
        while position < row.size {
            let request = self.chunk.min(row.size - position);
            let Some(bytes) = self.exact(&row.path, position, request)? else {
                return batch.finding(server, row, "rewrite-short-read");
            };
            data.extend_from_slice(&bytes);
            position += request;
        }
        let complete = data
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |last| last + 1);
        let acknowledged = offset
            .checked_add(u64::try_from(complete).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("offset overflow"))?;
        let tail_start = acknowledged.saturating_sub(self.tail);
        let tail_hash = if acknowledged == 0 {
            "-".to_owned()
        } else {
            let Some(bytes) = self.exact(&row.path, tail_start, acknowledged - tail_start)? else {
                return batch.finding(server, row, "rewrite-short-read");
            };
            protocol::digest(&bytes)
        };
        let mut offset = offset;
        for record in data[..complete].split_inclusive(|byte| *byte == b'\n') {
            let end = offset + u64::try_from(record.len()).map_err(io::Error::other)?;
            if protocol::noise(record) {
                batch.suppressed += 1;
            } else {
                write!(
                    batch.output,
                    "server={server} path={} off={offset}-{end} id={} bytes={} ",
                    row.path,
                    row.identity,
                    record.len()
                )?;
                batch.output.extend_from_slice(record);
                batch.content = true;
            }
            offset = end;
        }
        batch.positions.insert(
            key,
            Position {
                offset: acknowledged,
                high: acknowledged,
                observed: row.size,
                stamp: row.stamp.clone(),
                tail_start,
                tail_hash,
            },
        );
        Ok(())
    }

    pub fn poll(&self, server: &str, positions: &Positions) -> io::Result<Batch> {
        let rows = protocol::list(&self.remote("list")?)?;
        let mut batch = Batch {
            positions: positions.clone(),
            output: Vec::new(),
            findings: 0,
            content: false,
            suppressed: 0,
        };
        for row in rows {
            self.process(server, &row, &mut batch)?;
        }
        Ok(batch)
    }
}

impl Batch {
    fn finding(&mut self, server: &str, row: &Row, kind: &str) -> io::Result<()> {
        self.findings += 1;
        writeln!(
            self.output,
            "STEWARD-TRANSCRIPT-FINDING server={server} kind={kind} path={} id={}",
            row.path, row.identity
        )
    }
}
