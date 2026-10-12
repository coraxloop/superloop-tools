use super::*;
use std::cell::{Cell, RefCell};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::ExitStatusExt as _;

struct Fixture {
    root: tempfile::TempDir,
    data: RefCell<Vec<u8>>,
    elapsed: Cell<Duration>,
    reads: Cell<usize>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("config"), "Host alpha-steward\n").unwrap();
        fs::write(root.path().join("keys"), "fixture host key\n").unwrap();
        Self {
            root,
            data: RefCell::new(b"{\"type\":\"user\",\"message\":\"first\"}\n".to_vec()),
            elapsed: Cell::new(Duration::ZERO),
            reads: Cell::new(0),
        }
    }

    fn run(&self, watch: bool, advance: bool) -> (u8, String) {
        self.elapsed.set(Duration::ZERO);
        self.reads.set(0);
        let args = Poll {
            connection: Connection {
                ssh_config: Some(self.root.path().join("config")),
                known_hosts: self.root.path().join("keys"),
                exporter: "exporter".into(),
                server: "alpha".into(),
            },
            advance_cursor: advance,
            state_dir: Some(self.root.path().join("state")),
        };
        let settings = Settings {
            feed: Duration::from_millis(4000),
            total: Duration::from_millis(if watch { 300 } else { 4000 }),
            pause: Duration::from_millis(300),
            timeout: Duration::from_millis(1000),
            chunk: 65536,
            tail: 4096,
        };
        let mut output = Vec::new();
        let status = poll_with(args, watch, &mut output, &settings, self).unwrap();
        assert!(self.reads.get() > 0, "the caller must observe the exporter");
        (status, String::from_utf8(output).unwrap())
    }
}

impl transcript::Runtime for Fixture {
    fn elapsed(&self) -> Duration {
        self.elapsed.get()
    }

    fn sleep(&self, duration: Duration) {
        // Advance only after a completed poll. Scheduling the fixture cannot
        // consume the deadline before the event under test is observed.
        assert!(self.reads.get() > 0);
        self.elapsed.set(self.elapsed.get() + duration);
    }

    fn read(
        &self,
        _transport: &ssh::Transport,
        alias: &str,
        command: &str,
        timeout: Duration,
    ) -> io::Result<std::process::Output> {
        assert_eq!(alias, "alpha-steward");
        assert!(timeout > Duration::ZERO && timeout <= Duration::from_millis(1000));
        self.reads.set(self.reads.get() + 1);
        let words: Vec<_> = command.split_whitespace().collect();
        let data = self.data.borrow();
        let stdout = match words[1] {
            "list" => format!("project/session.jsonl\t{}\t1:1\t1:1\n", data.len()).into_bytes(),
            "read" => {
                assert_eq!(words[2], "'project/session.jsonl'");
                let offset: usize = words[3].parse().unwrap();
                let count: usize = words[4].parse().unwrap();
                data[offset..offset + count].to_vec()
            }
            other => panic!("unexpected exporter operation: {other}"),
        };
        Ok(std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout,
            stderr: Vec::new(),
        })
    }
}

fn metadata(path: &std::path::Path) -> Vec<i128> {
    let m = fs::metadata(path).unwrap();
    vec![
        m.ino().into(),
        m.mode().into(),
        m.uid().into(),
        m.gid().into(),
        m.len().into(),
        m.atime().into(),
        m.atime_nsec().into(),
        m.mtime().into(),
        m.mtime_nsec().into(),
        m.ctime().into(),
        m.ctime_nsec().into(),
    ]
}

/// ´test:unit:controlled-clock-preserves-bare-inspection-and-second-caller-cursor´
#[test]
fn controlled_clock_preserves_bare_inspection_and_second_caller_cursor() {
    let f = Fixture::new();
    for watch in [false, true] {
        let (status, output) = f.run(watch, false);
        assert_eq!(status, 0, "watch={watch}: {output}");
        assert!(output.contains("first"));
        assert!(!f.root.path().join("state").exists());
    }
    assert_eq!(f.run(false, true).0, 0);
    let path = f.root.path().join("state/cursor-alpha");
    let before = metadata(&path);
    for watch in [false, true] {
        let (status, output) = f.run(watch, false);
        assert_eq!(status, if watch { 2 } else { 0 });
        assert_eq!(metadata(&path), before);
        assert!(output.contains("STEWARD-TRANSCRIPT-DURATION-MS "));
        assert!(!output.contains("first"));
    }
    f.data
        .borrow_mut()
        .extend_from_slice(b"{\"type\":\"user\",\"message\":\"second\"}\npartial");
    let beta = f.root.path().join("state/cursor-beta");
    fs::write(&beta, "unrelated").unwrap();
    let beta_before = metadata(&beta);
    let (status, output) = f.run(false, true);
    assert_eq!(status, 0);
    assert!(output.contains("second"));
    assert!(!output.contains("first") && !output.contains("partial"));
    assert_eq!(metadata(&beta), beta_before);
    assert!(!f.run(false, false).1.contains("second"));
}
