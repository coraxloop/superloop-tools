mod cursor;
mod protocol;
mod ssh;
mod transcript;

#[cfg(test)]
mod polling_tests;

use clap::{Args, Parser, Subcommand};
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    version,
    about = "Send steward messages and inspect transcript records"
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    Send(Send),
    Transcript {
        #[command(subcommand)]
        command: Transcript,
    },
}

#[derive(Subcommand)]
enum Transcript {
    Poll(Poll),
    Watch(Poll),
}

#[derive(Args)]
struct Connection {
    #[arg(long)]
    ssh_config: Option<PathBuf>,
    #[arg(long)]
    known_hosts: PathBuf,
    #[arg(long, default_value = "/usr/local/libexec/superloop/transcript-export")]
    exporter: String,
    server: String,
}

#[derive(Args)]
struct Send {
    #[command(flatten)]
    connection: Connection,
    #[arg(long)]
    session: Option<String>,
    #[arg(required = true, num_args = 1..)]
    message: Vec<String>,
}

#[derive(Args)]
struct Poll {
    #[command(flatten)]
    connection: Connection,
    #[arg(long)]
    advance_cursor: bool,
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

impl Connection {
    fn open(&self) -> io::Result<(ssh::Transport, String)> {
        if !ssh::name(&self.server)
            || self.exporter.is_empty()
            || self.exporter.chars().any(char::is_control)
        {
            return Err(io::Error::other("invalid server or exporter"));
        }
        let alias = format!("{}-steward", self.server);
        let transport = ssh::Transport::new(
            self.ssh_config.clone(),
            self.known_hosts.clone(),
            std::slice::from_ref(&alias),
        )?;
        Ok((transport, alias))
    }
}

fn send(args: Send) -> io::Result<u8> {
    let start = Instant::now();
    let (transport, alias) = args.connection.open()?;
    let discovery = std::env::var("STEWARD_SEND_DISCOVERY_TIMEOUT_SECONDS")
        .map_or_else(|_| Ok(10), |s| s.parse::<u64>().map_err(io::Error::other))?;
    if discovery == 0 {
        return Err(io::Error::other("discovery timeout must be positive"));
    }
    let session = if let Some(session) = args.session {
        session
    } else {
        let output = transport.read(
            &alias,
            &format!("{} list", ssh::quote(&args.connection.exporter)),
            Duration::from_secs(discovery),
        )?;
        if !output.status.success() {
            return Err(io::Error::other("session discovery failed"));
        }
        let rows = protocol::list(&output.stdout)?;
        rows.iter()
            .filter(|row| {
                row.path.split('/').count() == 2
                    && std::path::Path::new(&row.path)
                        .extension()
                        .is_some_and(|extension| extension == "jsonl")
            })
            .max_by_key(|row| {
                (
                    row.stamp
                        .split(':')
                        .next()
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0),
                    &row.path,
                )
            })
            .and_then(|row| row.path.rsplit('/').next())
            .and_then(|name| name.strip_suffix(".jsonl"))
            .ok_or_else(|| {
                io::Error::other(format!(
                    "no steward session found on server: {}",
                    args.connection.server
                ))
            })?
            .to_owned()
    };
    if session.is_empty() || session.chars().any(char::is_control) {
        return Err(io::Error::other("invalid session"));
    }
    let remote = format!(
        "claude --resume {} --print -- {}",
        ssh::quote(&session),
        ssh::quote(&args.message.join(" "))
    );
    let status = transport.send(&alias, &remote)?;
    writeln!(
        io::stderr().lock(),
        "STEWARD-SEND-DURATION-MS {}",
        start.elapsed().as_millis()
    )?;
    Ok(status)
}

fn number(variable: &str, default: u64) -> io::Result<u64> {
    let value = std::env::var(variable).map_or_else(
        |_| Ok(default),
        |text| text.parse().map_err(io::Error::other),
    )?;
    if value == 0 {
        return Err(io::Error::other("read size must be positive"));
    }
    Ok(value)
}

struct Settings {
    feed: Duration,
    total: Duration,
    pause: Duration,
    timeout: Duration,
    chunk: u64,
    tail: u64,
}

impl Settings {
    fn load(watch: bool) -> io::Result<Self> {
        let feed = ssh::milliseconds("STEWARD_TRANSCRIPT_FEED_DEADLINE_MS", 500_000, true)?;
        Ok(Self {
            feed,
            total: if watch {
                ssh::milliseconds("STEWARD_TRANSCRIPT_WATCH_DEADLINE_MS", 3_600_000, true)?
            } else {
                feed
            },
            pause: ssh::milliseconds("STEWARD_TRANSCRIPT_WATCH_POLL_MS", 20_000, false)?,
            timeout: ssh::milliseconds("STEWARD_TRANSCRIPT_READ_TIMEOUT_MS", 10_000, true)?,
            chunk: number("STEWARD_TRANSCRIPT_READ_MAX_BYTES", 65_536)?,
            tail: number("STEWARD_TRANSCRIPT_TAIL_BYTES", 4_096)?,
        })
    }
}

fn expired(elapsed: Duration, server: &str, out: &mut impl io::Write) -> io::Result<u8> {
    writeln!(
        out,
        "STEWARD-TRANSCRIPT-DURATION-MS {} server={server}",
        elapsed.as_millis()
    )?;
    Ok(2)
}

fn poll(args: Poll, watch: bool, out: &mut impl io::Write) -> io::Result<u8> {
    let runtime = transcript::SystemRuntime::new();
    let settings = Settings::load(watch)?;
    poll_with(args, watch, out, &settings, &runtime)
}

fn poll_with(
    args: Poll,
    watch: bool,
    out: &mut impl io::Write,
    settings: &Settings,
    runtime: &dyn transcript::Runtime,
) -> io::Result<u8> {
    let (transport, alias) = args.connection.open()?;
    let state = args.state_dir.map_or_else(
        || ssh::home_path("dev/superloop-tools/steward-transcript-watch"),
        Ok,
    )?;
    let _guard = if args.advance_cursor {
        Some(cursor::Guard::acquire(&state, &args.connection.server)?)
    } else {
        None
    };
    let path = state.join(format!("cursor-{}", args.connection.server));
    let mut positions = cursor::read(&path)?
        .as_deref()
        .map(protocol::load)
        .transpose()?
        .unwrap_or_default();
    loop {
        let remaining = settings.total.saturating_sub(runtime.elapsed());
        if remaining.is_zero() {
            return expired(runtime.elapsed(), &args.connection.server, out);
        }
        let reader = transcript::Reader {
            transport: &transport,
            alias: &alias,
            exporter: &args.connection.exporter,
            runtime,
            start: runtime.elapsed(),
            deadline: settings.feed.min(remaining),
            timeout: settings.timeout,
            chunk: settings.chunk,
            tail: settings.tail,
        };
        let batch = match reader.poll(&args.connection.server, &positions) {
            Ok(batch) => batch,
            Err(_) if watch && runtime.elapsed() >= settings.total => {
                return expired(runtime.elapsed(), &args.connection.server, out);
            }
            Err(error) => return Err(error),
        };
        let changed = batch.positions != positions;
        let publish = !watch
            || batch.content
            || batch.findings > 0
            || batch.suppressed > 0
            || (args.advance_cursor && changed);
        if publish {
            out.write_all(&batch.output)?;
            if batch.suppressed > 0 {
                writeln!(
                    out,
                    "STEWARD-TRANSCRIPT-FILTERED server={} count={} file-history-snapshot={}",
                    args.connection.server, batch.suppressed, batch.suppressed
                )?;
            }
            writeln!(
                out,
                "STEWARD-TRANSCRIPT-DURATION-MS {} server={}",
                runtime.elapsed().as_millis(),
                args.connection.server
            )?;
            if batch.findings > 0 {
                writeln!(
                    out,
                    "STEWARD-TRANSCRIPT-WARNING findings={} content={} suppressed={}",
                    batch.findings,
                    u8::from(batch.content),
                    batch.suppressed
                )?;
            } else {
                writeln!(
                    out,
                    "STEWARD-TRANSCRIPT-{}",
                    if batch.content { "CONTENT" } else { "EMPTY" }
                )?;
            }
            out.flush()?;
            if args.advance_cursor && changed {
                cursor::save(&path, &protocol::encode(&batch.positions)?)?;
            }
        }
        positions = batch.positions;
        if !watch || batch.content || batch.findings > 0 {
            return Ok(0);
        }
        runtime.sleep(
            settings
                .pause
                .min(settings.total.saturating_sub(runtime.elapsed())),
        );
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
    let sending = matches!(cli.command, Action::Send(_));
    let result = match cli.command {
        Action::Send(args) => send(args),
        Action::Transcript {
            command: Transcript::Poll(args),
        } => poll(args, false, &mut io::stdout().lock()),
        Action::Transcript {
            command: Transcript::Watch(args),
        } => poll(args, true, &mut io::stdout().lock()),
    };
    result.map_or_else(
        |error| {
            let subject = if sending {
                "STEWARD-SEND"
            } else {
                "STEWARD-TRANSCRIPT"
            };
            let _wall = writeln!(
                io::stderr().lock(),
                "{subject}-DURATION-MS {}",
                start.elapsed().as_millis()
            );
            let _printed = writeln!(io::stderr().lock(), "{subject}-FAILED {error}");
            ExitCode::FAILURE
        },
        ExitCode::from,
    )
}
