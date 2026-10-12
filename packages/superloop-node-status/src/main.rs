use std::os::unix::process::ExitStatusExt as _;
mod ssh;

use clap::Parser;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

#[derive(Parser)]
#[command(
    version,
    about = "Compare loads of NODES through the selected loop's SSH aliases"
)]
struct Args {
    #[arg(long)]
    ssh_config: Option<PathBuf>,
    #[arg(long)]
    known_hosts: PathBuf,
    #[arg(value_name = "LOOP")]
    loop_name: String,
}

struct Load {
    cores: u32,
    values: [f64; 3],
    ratio: String,
}

fn parse(bytes: &[u8]) -> Option<Load> {
    let text = std::str::from_utf8(bytes).ok()?;
    let fields: Vec<_> = text.split_whitespace().collect();
    let [cores, one, five, fifteen] = fields.as_slice() else {
        return None;
    };
    let cores = cores.parse::<u32>().ok().filter(|count| *count > 0)?;
    let values = [
        one.parse::<f64>().ok()?,
        five.parse::<f64>().ok()?,
        fifteen.parse::<f64>().ok()?,
    ];
    if values.iter().any(|load| !load.is_finite() || *load < 0.0) {
        return None;
    }
    Some(Load {
        cores,
        values,
        ratio: format!("{:.3}", values[0] / f64::from(cores)),
    })
}

fn run(args: Args, out: &mut impl io::Write) -> io::Result<()> {
    if !ssh::name(&args.loop_name) {
        return Err(io::Error::other(format!(
            "configuration invalid loop {:?}",
            args.loop_name
        )));
    }
    let raw =
        std::env::var("NODES").map_err(|_| io::Error::other("configuration NODES is required"))?;
    let nodes: Vec<_> = raw.split_whitespace().collect();
    if nodes.is_empty() || nodes.iter().any(|node| !ssh::name(node)) {
        return Err(io::Error::other(format!(
            "configuration invalid NODES {raw:?}"
        )));
    }
    let aliases: Vec<_> = nodes
        .iter()
        .map(|node| format!("{node}-{}", args.loop_name))
        .collect();
    let transport = ssh::Transport::new(args.ssh_config, args.known_hosts, &aliases)?;
    let timeout = ssh::milliseconds("NODE_STATUS_TIMEOUT_MS", 8_000, true)
        .map_err(|error| io::Error::other(format!("configuration {error}")))?;
    let mut best: Option<(&str, f64)> = None;
    let mut failures = Vec::new();
    for (node, alias) in nodes.iter().zip(&aliases) {
        let result = transport
            .read(
                alias,
                "echo \"$(nproc) $(cut -d\" \" -f1-3 /proc/loadavg)\"",
                timeout,
            )
            .map_err(|error| io::Error::other(format!("transport alias={alias} spawn: {error}")))?;
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let last = stderr.lines().last().unwrap_or("");
            let cause = match result.status.code() {
                Some(124 | 137) => format!(
                    "transport alias={alias} deadline_ms={} expired",
                    timeout.as_millis()
                ),
                Some(code @ 125..=127) => {
                    format!("transport alias={alias} wrapper_exit={code} stderr_last={last:?}")
                }
                Some(code) => {
                    format!("transport alias={alias} ssh_exit={code} stderr_last={last:?}")
                }
                None => format!(
                    "transport alias={alias} ssh_signal={} stderr_last={last:?}",
                    result.status.signal().unwrap_or_default()
                ),
            };
            writeln!(out, "{node} unreachable {cause}")?;
            failures.push(cause);
            continue;
        }
        let Some(load) = parse(&result.stdout) else {
            let cause = format!(
                "load alias={alias} unparsed={:?}",
                String::from_utf8_lossy(&result.stdout)
            );
            writeln!(out, "{node} invalid-load {cause}")?;
            failures.push(cause);
            continue;
        };
        writeln!(
            out,
            "{node} cores={} load={} {} {} ratio={}",
            load.cores, load.values[0], load.values[1], load.values[2], load.ratio
        )?;
        let ratio = load.ratio.parse::<f64>().map_err(io::Error::other)?;
        if best.is_none_or(|(_, previous)| ratio < previous) {
            best = Some((node, ratio));
        }
    }
    let (node, _) = best.ok_or_else(|| io::Error::other(failures.join("; ")))?;
    writeln!(out, "LIGHTER={node}")
}

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit(env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"), None);
    let start = Instant::now();
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => {
            let code = error.exit_code();
            let _printed = error.print();
            return ExitCode::from(u8::try_from(code).unwrap_or(2));
        }
    };
    let result = run(args, &mut io::stdout().lock());
    let wall = writeln!(
        io::stdout().lock(),
        "NODE-STATUS-DURATION-MS {}",
        start.elapsed().as_millis()
    );
    if let Err(error) = result.and(wall) {
        let _printed = writeln!(io::stderr().lock(), "NODE-STATUS-FAILED {error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
