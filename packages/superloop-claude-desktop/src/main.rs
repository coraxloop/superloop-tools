mod codec;
mod files;
mod groups;
mod sessions;

use clap::{Parser, Subcommand};
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

#[derive(Parser)]
#[command(
    version,
    about = "Maintain Claude Desktop application state; fixture roots isolate every inspected input"
)]
struct Cli {
    #[arg(long, global = true)]
    fixture_root: Option<PathBuf>,
    #[arg(long, global = true)]
    leveldb_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    sessions_root: Option<PathBuf>,
    #[arg(long, global = true)]
    sessions_registry: Option<PathBuf>,
    #[arg(long, global = true)]
    projects_root: Option<PathBuf>,
    #[arg(long, global = true)]
    proc_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    SyncGroups {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        migrate: bool,
    },
    MergeSessions {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        check: bool,
        #[arg(long)]
        allow_live: bool,
        #[arg(long)]
        prefer_successor: bool,
    },
}

struct Paths {
    leveldb: PathBuf,
    lock: PathBuf,
    sessions: PathBuf,
    registry: PathBuf,
    projects: PathBuf,
    proc_root: PathBuf,
}

fn configured(given: Option<PathBuf>, variable: &str, default: PathBuf, fixture: bool) -> PathBuf {
    given
        .or_else(|| {
            if fixture || variable.is_empty() {
                None
            } else {
                std::env::var_os(variable)
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
            }
        })
        .unwrap_or(default)
}

impl Cli {
    fn resolve(&self) -> io::Result<Paths> {
        let fixture = self.fixture_root.is_some();
        let base = self.fixture_root.clone().map_or_else(
            || {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .ok_or_else(|| io::Error::other("HOME or fixture-root required"))
            },
            Ok,
        )?;
        let base = std::path::absolute(base)?;
        let app = base.join(if fixture {
            "application"
        } else {
            ".config/Claude"
        });
        let leveldb = configured(
            self.leveldb_dir.clone(),
            "CCD_LEVELDB_DIR",
            app.join("Local Storage/leveldb"),
            fixture,
        );
        let lock = leveldb.join("LOCK");
        Ok(Paths {
            leveldb,
            lock,
            sessions: configured(
                self.sessions_root.clone(),
                "CCD_SESSIONS_ROOT",
                app.join("claude-code-sessions"),
                fixture,
            ),
            registry: configured(
                self.sessions_registry.clone(),
                "CCD_SESSIONS_REGISTRY",
                base.join(if fixture {
                    "registry"
                } else {
                    ".claude/sessions"
                }),
                fixture,
            ),
            projects: configured(
                self.projects_root.clone(),
                "",
                base.join(if fixture {
                    "projects"
                } else {
                    ".claude/projects"
                }),
                fixture,
            ),
            proc_root: self.proc_root.clone().unwrap_or_else(|| {
                if fixture {
                    base.join("proc")
                } else {
                    PathBuf::from("/proc")
                }
            }),
        })
    }
}

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit(env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"), None);
    let started = Instant::now();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            let _printed = error.print();
            return ExitCode::from(code);
        }
    };
    let check_mode = matches!(&cli.command, Action::MergeSessions { check: true, .. });
    let result = cli.resolve().and_then(|paths| {
        let mut out = io::stdout().lock();
        match cli.command {
            Action::SyncGroups { dry_run, migrate } => {
                groups::run(&paths, dry_run, migrate, &mut out)
            }
            Action::MergeSessions {
                dry_run,
                check,
                allow_live,
                prefer_successor,
            } => sessions::run(
                &paths,
                if check {
                    sessions::Mode::Check
                } else if dry_run {
                    sessions::Mode::DryRun
                } else {
                    sessions::Mode::Apply
                },
                allow_live,
                prefer_successor,
                &mut out,
            ),
        }
    });
    let _wall = writeln!(
        io::stdout().lock(),
        "CCD-DURATION-MS {}",
        started.elapsed().as_millis()
    );
    result.map_or_else(
        |error| {
            let _printed = writeln!(io::stderr().lock(), "CCD-FAILED {error}");
            ExitCode::from(if check_mode { 2 } else { 1 })
        },
        ExitCode::from,
    )
}
