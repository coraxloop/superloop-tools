mod cursor;
mod ssh;

use clap::{Args, Parser, Subcommand};
use std::collections::BTreeMap;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::{ExitCode, Output};
use std::time::{Duration, Instant};

trait Clock {
    type Tick: Copy;

    fn now(&self) -> Self::Tick;
    fn elapsed(&self, since: Self::Tick) -> Duration;
    fn sleep(&self, delay: Duration);
}

struct SystemClock;

impl Clock for SystemClock {
    type Tick = Instant;

    fn now(&self) -> Self::Tick {
        Instant::now()
    }

    fn elapsed(&self, since: Self::Tick) -> Duration {
        since.elapsed()
    }

    fn sleep(&self, delay: Duration) {
        std::thread::sleep(delay);
    }
}

trait Reader {
    fn read(&self, alias: &str, remote: &str, limit: Duration) -> io::Result<Output>;
}

impl Reader for ssh::Transport {
    fn read(&self, alias: &str, remote: &str, limit: Duration) -> io::Result<Output> {
        Self::read(self, alias, remote, limit)
    }
}

#[derive(Parser)]
#[command(
    version,
    about = "Read correspondence journals; saving a shared cursor is explicit"
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    Poll(Options),
    Watch(Options),
}

#[derive(Args)]
struct Options {
    #[arg(long)]
    advance_cursor: bool,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long)]
    ssh_config: Option<PathBuf>,
    #[arg(long)]
    known_hosts: PathBuf,
    #[arg(required = true, num_args = 1..)]
    hosts: Vec<String>,
}

struct Poller<R: Reader> {
    transport: R,
    state: PathBuf,
    cursors: BTreeMap<String, String>,
    guards: Vec<cursor::Guard>,
    advance: bool,
}

impl<R: Reader> Poller<R> {
    fn new(options: Options, transport: R) -> io::Result<Self> {
        let state = options.state_dir.map_or_else(
            || ssh::home_path("dev/superloop-tools/correspondence-watch"),
            Ok,
        )?;
        let mut cursors = BTreeMap::new();
        let mut guards = Vec::new();
        for host in options.hosts {
            if cursors.contains_key(&host) {
                return Err(io::Error::other("duplicate host"));
            }
            if options.advance_cursor {
                guards.push(cursor::Guard::acquire(&state, &host)?);
            }
            let bytes = cursor::read(&state.join(format!("cursor-{host}")))?.unwrap_or_default();
            let value = String::from_utf8(bytes).map_err(|_| io::Error::other("invalid cursor"))?;
            if value.contains(['\r', '\n', '\0']) {
                return Err(io::Error::other("invalid cursor"));
            }
            cursors.insert(host, value);
        }
        Ok(Self {
            transport,
            state,
            cursors,
            guards,
            advance: options.advance_cursor,
        })
    }

    fn host(
        &mut self,
        host: &str,
        limit: Duration,
        out: &mut impl io::Write,
    ) -> io::Result<Option<bool>> {
        let previous = &self.cursors[host];
        let after = if previous.is_empty() {
            String::new()
        } else {
            format!(" --after-cursor {}", ssh::quote(previous))
        };
        let remote = format!(
            "sudo journalctl -t correspondence-watch{after} --show-cursor -o cat 2>/dev/null"
        );
        let output = self.transport.read(host, &remote, limit)?;
        if !output.status.success() {
            writeln!(out, "host={host} SSH-FAILED")?;
            return Ok(None);
        }
        let text = String::from_utf8(output.stdout)
            .map_err(|_| io::Error::other("invalid journal encoding"))?;
        let mut next = None;
        let mut content = false;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("-- cursor: ") {
                if value.is_empty() || value.contains(['\r', '\0']) {
                    return Err(io::Error::other("invalid journal cursor"));
                }
                next = Some(value.to_owned());
            } else if !line.trim().is_empty() {
                content |= line.split_whitespace().any(|word| word == "from=user");
                writeln!(out, "host={host} {line}")?;
            }
        }
        out.flush()?;
        if let Some(next) = next {
            if self.advance {
                cursor::save(&self.state.join(format!("cursor-{host}")), next.as_bytes())?;
            }
            self.cursors.insert(host.to_owned(), next);
        }
        Ok(Some(content))
    }
}

#[derive(Clone, Copy)]
struct Limits {
    feed: Duration,
    pause: Duration,
    floor: Duration,
    total: Duration,
}

fn run(action: Action, out: &mut impl io::Write) -> io::Result<u8> {
    let clock = SystemClock;
    let start = clock.now();
    let (options, watch) = match action {
        Action::Poll(options) => (options, false),
        Action::Watch(options) => (options, true),
    };
    let feed_limit = ssh::milliseconds("CORRESPONDENCE_FEED_DEADLINE_MS", 500_000, true)?;
    let pause = ssh::milliseconds("CORRESPONDENCE_FEED_POLL_MS", 20_000, false)?;
    let floor = ssh::milliseconds(
        "CORRESPONDENCE_FEED_POLL_FLOOR_MS",
        u64::try_from(pause.as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(20),
        true,
    )?;
    let total = if watch {
        ssh::milliseconds("CORRESPONDENCE_WATCH_DEADLINE_MS", 3_600_000, true)?
    } else {
        feed_limit
    };
    let transport = ssh::Transport::new(
        options.ssh_config.clone(),
        options.known_hosts.clone(),
        &options.hosts,
    )?;
    run_core(
        options,
        transport,
        Limits {
            feed: feed_limit,
            pause,
            floor,
            total,
        },
        watch,
        out,
        &clock,
        start,
    )
}

fn run_core<C: Clock, R: Reader>(
    options: Options,
    transport: R,
    limits: Limits,
    watch: bool,
    out: &mut impl io::Write,
    clock: &C,
    start: C::Tick,
) -> io::Result<u8> {
    let mut poller = Poller::new(options, transport)?;
    // Keep the guards alive through publication and every subsequent read.
    let _held = poller.guards.len();
    let hosts: Vec<_> = poller.cursors.keys().cloned().collect();
    loop {
        let round_start = clock.now();
        let round_limit = limits
            .feed
            .min(limits.total.saturating_sub(clock.elapsed(start)));
        if round_limit.is_zero() {
            writeln!(out, "FEED-DURATION-MS {}", clock.elapsed(start).as_millis())?;
            return Ok(2);
        }
        let mut polls = 0;
        let mut failures = 0;
        let mut content = false;
        loop {
            for host in &hosts {
                let remaining = round_limit.saturating_sub(clock.elapsed(round_start));
                if remaining <= limits.floor {
                    break;
                }
                polls += 1;
                match poller.host(host, remaining, out)? {
                    Some(found) => content |= found,
                    None => failures += 1,
                }
            }
            let remaining = round_limit.saturating_sub(clock.elapsed(round_start));
            if content || remaining <= limits.floor {
                break;
            }
            clock.sleep(limits.pause.min(remaining.saturating_sub(limits.floor)));
        }
        let failed = polls > 0 && failures == polls;
        if !watch || content || failures > 0 {
            if !content {
                clock.sleep(round_limit.saturating_sub(clock.elapsed(round_start)));
            }
            writeln!(
                out,
                "FEED-DURATION-MS {} hosts={} ssh_fails={failures} polls={polls}",
                clock.elapsed(start).as_millis(),
                hosts.join(" ")
            )?;
            if failed {
                writeln!(
                    out,
                    "FEED-FAILED all ssh polls failed: ssh_fails={failures} polls={polls}"
                )?;
                return Ok(1);
            }
            if failures > 0 {
                writeln!(
                    out,
                    "FEED-WARNING partial ssh failure: ssh_fails={failures} polls={polls}"
                )?;
            }
            writeln!(out, "FEED-{}", if content { "CONTENT" } else { "EMPTY" })?;
            return Ok(0);
        }
        clock.sleep(round_limit.saturating_sub(clock.elapsed(round_start)));
    }
}

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit(env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"), None);
    let start = Instant::now();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = u8::from(error.use_stderr());
            let _printed = error.print();
            return ExitCode::from(code);
        }
    };
    run(cli.command, &mut io::stdout().lock()).map_or_else(
        |error| {
            let _printed = writeln!(
                io::stderr().lock(),
                "FEED-FAILED {error} wall_ms={}",
                start.elapsed().as_millis()
            );
            ExitCode::FAILURE
        },
        ExitCode::from,
    )
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::PathBuf;
    use std::process::{ExitStatus, Output};
    use std::rc::Rc;
    use std::time::Duration;

    use super::{Clock, Limits, Options, Reader, run_core};

    #[derive(Clone)]
    struct SteppedClock(Rc<Cell<Duration>>);

    impl Clock for SteppedClock {
        type Tick = Duration;

        fn now(&self) -> Self::Tick {
            self.0.get()
        }

        fn elapsed(&self, since: Self::Tick) -> Duration {
            self.now().saturating_sub(since)
        }

        fn sleep(&self, delay: Duration) {
            self.0.set(self.now().saturating_add(delay));
        }
    }

    #[derive(Clone, Copy)]
    struct Reply {
        body: &'static str,
        status: i32,
        work_ms: u64,
    }

    impl Reply {
        fn empty(work_ms: u64) -> Self {
            Self {
                body: "-- cursor: next\n",
                status: 0,
                work_ms,
            }
        }

        fn failed(work_ms: u64) -> Self {
            Self {
                body: "",
                status: 124,
                work_ms,
            }
        }
    }

    #[derive(Clone)]
    struct Replies {
        clock: SteppedClock,
        queued: Rc<RefCell<VecDeque<Reply>>>,
        calls: Rc<RefCell<Vec<(String, Duration)>>>,
    }

    impl Reader for Replies {
        fn read(&self, alias: &str, _remote: &str, limit: Duration) -> std::io::Result<Output> {
            self.calls.borrow_mut().push((alias.to_owned(), limit));
            let reply = self
                .queued
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Reply::empty(0));
            self.clock.sleep(Duration::from_millis(reply.work_ms));
            Ok(Output {
                status: ExitStatus::from_raw(reply.status << 8),
                stdout: reply.body.as_bytes().to_vec(),
                stderr: Vec::new(),
            })
        }
    }

    struct Outcome {
        code: u8,
        text: String,
        calls: Vec<(String, Duration)>,
        wall: Duration,
        cursor: Option<Vec<u8>>,
    }

    fn check(
        watch: bool,
        hosts: &[&str],
        limits_ms: (u64, u64, u64, u64),
        replies: &[Reply],
    ) -> Outcome {
        check_with_cursor(watch, hosts, limits_ms, replies, false, None)
    }

    fn check_with_cursor(
        watch: bool,
        hosts: &[&str],
        limits_ms: (u64, u64, u64, u64),
        replies: &[Reply],
        advance_cursor: bool,
        initial_cursor: Option<&[u8]>,
    ) -> Outcome {
        let directory = tempfile::tempdir().expect("state fixture");
        let cursor = directory.path().join("cursor-alpha");
        if let Some(bytes) = initial_cursor {
            std::fs::write(&cursor, bytes).expect("initial cursor");
        }
        let clock = SteppedClock(Rc::new(Cell::new(Duration::ZERO)));
        let transport = Replies {
            clock: clock.clone(),
            queued: Rc::new(RefCell::new(replies.iter().copied().collect())),
            calls: Rc::new(RefCell::new(Vec::new())),
        };
        let observed = transport.clone();
        let options = Options {
            advance_cursor,
            state_dir: Some(directory.path().to_path_buf()),
            ssh_config: None,
            known_hosts: PathBuf::new(),
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        };
        let (feed, pause, floor, total) = limits_ms;
        let limits = Limits {
            feed: Duration::from_millis(feed),
            pause: Duration::from_millis(pause),
            floor: Duration::from_millis(floor),
            total: Duration::from_millis(total),
        };
        let mut bytes = Vec::new();
        let start = clock.now();
        let code = run_core(options, transport, limits, watch, &mut bytes, &clock, start)
            .expect("stepped feed runs");
        assert!(observed.queued.borrow().is_empty(), "unused replies");
        Outcome {
            code,
            text: String::from_utf8(bytes).expect("feed output is UTF-8"),
            calls: observed.calls.borrow().clone(),
            wall: clock.now(),
            cursor: std::fs::read(cursor).ok(),
        }
    }

    /// # Panics
    /// Panics only if a stepped watch loses its round count, total budget, or exit-2 evidence.
    /// ´test:unit:stepped-watch-expires-after-empty-rounds-and-cuts-final-round´
    #[test]
    fn stepped_watch_expires_after_empty_rounds_and_cuts_final_round() {
        let two = check(
            true,
            &["alpha"],
            (100, 10, 50, 200),
            &[Reply::empty(50), Reply::empty(50)],
        );
        assert_eq!(two.code, 2);
        assert_eq!(two.wall, Duration::from_millis(200));
        assert_eq!(two.calls.len(), 2);
        assert_eq!(two.text, "FEED-DURATION-MS 200\n");

        let cut = check(
            true,
            &["alpha"],
            (100, 10, 50, 170),
            &[Reply::empty(50), Reply::empty(20)],
        );
        assert_eq!(cut.code, 2);
        assert_eq!(cut.wall, Duration::from_millis(170));
        assert_eq!(cut.calls.len(), 2);
        assert_eq!(cut.calls[1].1, Duration::from_millis(70));
        assert_eq!(cut.text, "FEED-DURATION-MS 170\n");
    }

    /// # Panics
    /// Panics only if a stepped poll misclassifies empty, admin, content, or floor evidence.
    /// ´test:unit:stepped-poll-distinguishes-empty-admin-content-and-floor´
    #[test]
    fn stepped_poll_distinguishes_empty_admin_content_and_floor() {
        let empty = check(false, &["alpha"], (100, 10, 50, 100), &[Reply::empty(50)]);
        assert_eq!(empty.code, 0);
        assert_eq!(empty.calls.len(), 1);
        assert!(empty.text.ends_with("polls=1\nFEED-EMPTY\n"));

        let admin = check(
            false,
            &["alpha"],
            (100, 10, 50, 100),
            &[Reply {
                body: "from=admin sender=test file=/messages/admin\n-- cursor: next\n",
                status: 0,
                work_ms: 50,
            }],
        );
        assert_eq!(admin.code, 0);
        assert!(admin.text.contains("host=alpha from=admin"));
        assert!(admin.text.ends_with("FEED-EMPTY\n"));

        let content = check(
            true,
            &["alpha"],
            (100, 10, 20, 200),
            &[
                Reply {
                    body: "from=admin sender=test file=/messages/admin\n-- cursor: one\n",
                    status: 0,
                    work_ms: 10,
                },
                Reply {
                    body: "from=user sender=test file=/messages/user\n-- cursor: two\n",
                    status: 0,
                    work_ms: 10,
                },
            ],
        );
        assert_eq!(content.code, 0);
        assert_eq!(content.calls.len(), 2);
        assert!(content.text.contains("host=alpha from=admin"));
        assert!(content.text.contains("host=alpha from=user"));
        assert!(content.text.ends_with("FEED-CONTENT\n"));

        let floor = check(false, &["alpha"], (40, 10, 50, 40), &[]);
        assert_eq!(floor.code, 0);
        assert_eq!(floor.calls, []);
        assert!(floor.text.ends_with("polls=0\nFEED-EMPTY\n"));
    }

    /// # Panics
    /// Panics only if a stepped failed transport loses its count, warning, or failure verdict.
    /// ´test:unit:stepped-poll-keeps-partial-total-and-over-budget-failures´
    #[test]
    fn stepped_poll_keeps_partial_total_and_over_budget_failures() {
        let partial = check(
            false,
            &["alpha", "beta"],
            (100, 20, 20, 100),
            &[Reply::failed(30), Reply::empty(30)],
        );
        assert_eq!(partial.code, 0);
        assert_eq!(partial.calls.len(), 2);
        assert!(partial.text.contains("ssh_fails=1 polls=2"));
        assert!(partial.text.contains("FEED-WARNING partial ssh failure"));
        assert!(partial.text.ends_with("FEED-EMPTY\n"));

        let failed = check(false, &["alpha"], (100, 10, 50, 100), &[Reply::failed(50)]);
        assert_eq!(failed.code, 1);
        assert!(failed.text.contains("host=alpha SSH-FAILED"));
        assert!(
            failed
                .text
                .ends_with("FEED-FAILED all ssh polls failed: ssh_fails=1 polls=1\n")
        );

        let watch_failed = check(true, &["alpha"], (100, 10, 50, 200), &[Reply::failed(50)]);
        assert_eq!(watch_failed.code, 1);
        assert!(
            watch_failed
                .text
                .contains("FEED-FAILED all ssh polls failed")
        );

        let slow = check(false, &["alpha"], (100, 10, 50, 100), &[Reply::failed(120)]);
        assert_eq!(slow.code, 1);
        assert_eq!(slow.calls[0].1, Duration::from_millis(100));
        assert_eq!(slow.wall, Duration::from_millis(120));
        assert!(slow.text.contains("host=alpha SSH-FAILED"));
    }

    /// # Panics
    /// Panics only if a failed transport changes a previously saved cursor.
    /// ´test:unit:stepped-failed-transport-does-not-advance-cursor´
    #[test]
    fn stepped_failed_transport_does_not_advance_cursor() {
        let failed = check_with_cursor(
            false,
            &["alpha"],
            (100, 10, 50, 100),
            &[Reply::failed(50)],
            true,
            Some(b"old"),
        );
        assert_eq!(failed.code, 1);
        assert_eq!(failed.cursor.as_deref(), Some(b"old".as_slice()));
    }
}
