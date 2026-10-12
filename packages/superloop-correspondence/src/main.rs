mod cursor;
mod ssh;

use clap::{Args, Parser, Subcommand};
use std::collections::BTreeMap;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

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

struct Poller {
    transport: ssh::Transport,
    state: PathBuf,
    cursors: BTreeMap<String, String>,
    guards: Vec<cursor::Guard>,
    advance: bool,
}

impl Poller {
    fn new(options: Options) -> io::Result<Self> {
        let transport =
            ssh::Transport::new(options.ssh_config, options.known_hosts, &options.hosts)?;
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

fn run(action: Action, out: &mut impl io::Write) -> io::Result<u8> {
    let start = Instant::now();
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
    let mut poller = Poller::new(options)?;
    // Keep the guards alive through publication and every subsequent read.
    let _held = poller.guards.len();
    let hosts: Vec<_> = poller.cursors.keys().cloned().collect();
    loop {
        let round_start = Instant::now();
        let round_limit = feed_limit.min(total.saturating_sub(start.elapsed()));
        if round_limit.is_zero() {
            writeln!(out, "FEED-DURATION-MS {}", start.elapsed().as_millis())?;
            return Ok(2);
        }
        let mut polls = 0;
        let mut failures = 0;
        let mut content = false;
        loop {
            for host in &hosts {
                let remaining = round_limit.saturating_sub(round_start.elapsed());
                if remaining <= floor {
                    break;
                }
                polls += 1;
                match poller.host(host, remaining, out)? {
                    Some(found) => content |= found,
                    None => failures += 1,
                }
            }
            let remaining = round_limit.saturating_sub(round_start.elapsed());
            if content || remaining <= floor {
                break;
            }
            std::thread::sleep(pause.min(remaining.saturating_sub(floor)));
        }
        let failed = polls > 0 && failures == polls;
        if !watch || content || failures > 0 {
            if !content {
                std::thread::sleep(round_limit.saturating_sub(round_start.elapsed()));
            }
            writeln!(
                out,
                "FEED-DURATION-MS {} hosts={} ssh_fails={failures} polls={polls}",
                start.elapsed().as_millis(),
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
        std::thread::sleep(round_limit.saturating_sub(round_start.elapsed()));
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
