use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{CommandFactory as _, Parser};
use minijinja::Environment;
use superloop_chat_export::agents::{attach, load_agents};
use superloop_chat_export::folder::{Folder, create_apart};
use superloop_chat_export::input::{Project, Reached};
use superloop_chat_export::load::{Heads, LoopSource};
use superloop_chat_export::names::is_segment;
use superloop_chat_export::plan::{PAGE_BUDGET, Summary, plan, write_dump};
use superloop_chat_export::registry::{project_slug, read_registry};
use superloop_chat_export::render::{
    Outcome, RenderError, Settings, render_loop, write_loops_index,
};
use superloop_chat_export::templates::with_templates;
use superloop_chat_export::tree::Tree;
use superloop_chat_export::view::MIN_BLOCK_BYTES;

#[derive(Parser)]
#[command(
    name = "superloop-chat-export",
    version,
    about = "Render registered loops' session transcripts as HTML pages"
)]
struct Args {
    /// Export a named loop; repeatable.
    #[arg(
        long = "loop",
        value_name = "NAME",
        required_unless_present = "all",
        conflicts_with = "all"
    )]
    loops: Vec<String>,
    /// Export every registered loop.
    #[arg(long)]
    all: bool,
    /// The loop registry [default: ~/.local/share/superloop-tools/loops.d].
    #[arg(long, value_name = "DIR")]
    registry: Option<PathBuf>,
    /// The harness's project directories [default: ~/.claude/projects].
    #[arg(long, value_name = "DIR")]
    projects: Option<PathBuf>,
    /// Where the pages are written [default: ~/chats].
    #[arg(long, value_name = "DIR")]
    chats: Option<PathBuf>,
    /// The most bytes of one text block a page shows, at least 64.
    #[arg(long, value_name = "N", default_value_t = 16384, value_parser = block_limit)]
    max_block_bytes: u64,
    /// Write the page plan of the selected loops as JSON lines, for checking.
    #[arg(long, value_name = "FILE", hide = true)]
    dump_plan: Option<PathBuf>,
}

/// The block limit the command line names, refused below the floor at which a
/// cut text still keeps its opening and says what it omits.
fn block_limit(text: &str) -> Result<u64, String> {
    let limit: u64 = text
        .parse()
        .map_err(|_| format!("{text:?} is not a number of bytes"))?;
    if usize::try_from(limit).is_ok_and(|limit| limit < MIN_BLOCK_BYTES) {
        return Err(format!(
            "{limit} is below the least block limit, {MIN_BLOCK_BYTES} bytes, at which a cut text still keeps its opening and says how many bytes it omits"
        ));
    }
    Ok(limit)
}

/// A failure that ends the run: a usage error (status 2) or an unreadable
/// input (status 1).
enum Failure {
    Usage(String),
    Io(String),
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// Writes a message to the error stream; the stream failing leaves nothing
/// else to tell.
fn tell(message: &str) {
    let _ignored = writeln!(io::stderr().lock(), "superloop-chat-export: {message}");
}

fn home_default(given: Option<PathBuf>, relative: &str) -> Result<PathBuf, Failure> {
    given.map_or_else(
        || {
            std::env::var_os("HOME")
                .map(|home| Path::new(&home).join(relative))
                .ok_or_else(|| {
                    Failure::Usage(format!("HOME is unset; pass the directory for {relative}"))
                })
        },
        Ok,
    )
}

fn readable_directory(path: &Path, role: &str) -> Result<(), Failure> {
    if path.is_dir() && std::fs::read_dir(path).is_ok() {
        Ok(())
    } else {
        Err(Failure::Io(format!(
            "unreadable {role} directory: {}",
            path.display()
        )))
    }
}

/// The selected loops among the registered ones whose names are of the
/// grammar; a name outside it is left out wherever it would be selected.
fn selected(
    loops: Vec<String>,
    all: bool,
    registered: &BTreeMap<String, String>,
) -> Result<Vec<String>, Failure> {
    let mut names: Vec<String> = if all {
        registered
            .keys()
            .filter(|name| is_segment(name))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let unknown: Vec<&str> = loops
        .iter()
        .filter(|name| !registered.contains_key(*name))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        return Err(Failure::Usage(format!(
            "unknown loop: {}",
            unknown.join(", ")
        )));
    }
    for name in loops {
        if is_segment(&name) && !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

/// Creates the plan dump through its checked folder's descriptor, refusing a
/// folder under the projects or the output directory and any existing file.
fn create_dump(path: &Path, projects: &Path, chats: &Path) -> Result<BufWriter<File>, Failure> {
    create_apart(path, &[(projects, "projects"), (chats, "output")])
        .map(BufWriter::new)
        .map_err(|error| Failure::Io(format!("refused plan dump {}: {error}", path.display())))
}

/// What every loop's export shares.
struct Export<'a> {
    environment: &'a Environment<'static>,
    chats: &'a Folder,
    chats_path: &'a Path,
    /// The operator's projects folder, which every loop's project folder
    /// lies in.
    projects: &'a Path,
    limit: usize,
}

/// Names on the error stream the foreign files a loop's render left in place.
fn tell_foreign(name: &str, output: &Path, outcome: &Outcome) {
    if outcome.files_foreign == 0 {
        return;
    }
    let more = outcome.files_foreign - outcome.foreign.len();
    let tail = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    let listed: Vec<String> = outcome
        .foreign
        .iter()
        .map(|path| format!("{path:?}"))
        .collect();
    tell(&format!(
        "loop {name}: left {} files in {} that the program does not own: {}{tail}",
        outcome.files_foreign,
        output.display(),
        listed.join(", ")
    ));
}

/// Names on the error stream the first few transcript files a loop's source
/// leaves unread: for their names, for an agent id another file gives, or for
/// their kind.
fn tell_unread<'p>(name: &str, source: &LoopSource, skipped: impl Iterator<Item = &'p PathBuf>) {
    for path in source.ignored.iter().take(5) {
        tell(&format!(
            "loop {name}: left unread {:?}: a session file is STEM.jsonl and a subagent file agent-ID.jsonl, each STEM and ID a segment of the name grammar",
            path.display().to_string()
        ));
    }
    for (path, first) in source.repeated.iter().take(5) {
        tell(&format!(
            "loop {name}: left unread {:?}: its agent id is that of {:?}, whose thread is rendered",
            path.display().to_string(),
            first.display().to_string()
        ));
    }
    for path in skipped.take(5) {
        tell(&format!(
            "loop {name}: left unread {:?}: a link, a pipe or another entry that is not the regular file or the folder read there",
            path.display().to_string()
        ));
    }
}

/// Opens a loop's project folder in the projects folder without following a
/// link; none, with the loop's report line printed, when no folder stands at
/// its name.
fn open_project(
    export: &Export<'_>,
    name: &str,
    slug: &str,
    started: Instant,
    out: &mut impl Write,
) -> Result<Option<Project>, Failure> {
    match Project::open(export.projects, OsStr::new(slug)) {
        Ok(Reached::Found(project)) => return Ok(Some(project)),
        Ok(Reached::Absent) => {}
        Ok(Reached::Refused) => tell(&format!(
            "loop {name}: left unread {:?}: the loop's project folder is a link or not a folder",
            export.projects.join(slug).display().to_string()
        )),
        Err(error) => {
            return Err(Failure::Io(format!(
                "unreadable projects directory {}: {error}",
                export.projects.display()
            )));
        }
    }
    writeln!(
        out,
        "loop={name} files=0 status=no-projects-directory wall_ms={}",
        started.elapsed().as_millis()
    )
    .map_err(Failure::from)?;
    Ok(None)
}

/// Exports one loop and prints its report line; returns whether the loop was
/// refused because a foreign entry stands where the run writes.
fn export_loop(
    export: &Export<'_>,
    name: &str,
    slug: &str,
    dump: Option<&mut BufWriter<File>>,
    out: &mut impl Write,
) -> Result<bool, Failure> {
    let started = Instant::now();
    let Some(project) = open_project(export, name, slug, started, out)? else {
        return Ok(false);
    };
    let unreadable = |error: io::Error| {
        Failure::Io(format!(
            "unreadable transcript under {}: {error}",
            project.path.display()
        ))
    };
    let source = LoopSource::discover(&project).map_err(unreadable)?;
    let heads = Heads::load(&source).map_err(unreadable)?;
    let (mut agents, skipped_agents) = load_agents(&source.agents).map_err(unreadable)?;
    tell_unread(name, &source, heads.skipped.iter().chain(&skipped_agents));
    attach(&mut agents, &heads);
    let tree = Tree::build(&heads);
    let pages = plan(&heads, &tree, &agents, PAGE_BUDGET);
    if let Some(dump) = dump {
        write_dump(dump, &heads, &tree, &agents, &pages).map_err(Failure::from)?;
    }
    let output = export.chats_path.join(name);
    let refuse = |out: &mut dyn Write, path: &str| -> Result<bool, Failure> {
        tell(&format!(
            "refused loop {name}: {:?} stands where the run writes, and the program does not own it; nothing was written",
            output.join(path).display().to_string()
        ));
        writeln!(
            out,
            "loop={name} status=refused wall_ms={}",
            started.elapsed().as_millis()
        )
        .map_err(Failure::from)?;
        Ok(true)
    };
    let folder = match export.chats.child(name) {
        Ok(folder) => folder,
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => return refuse(out, ""),
        Err(error) => {
            return Err(Failure::Io(format!(
                "cannot open {}: {error}",
                output.display()
            )));
        }
    };
    let settings = Settings {
        name,
        project: &project.path,
        folder: &folder,
        limit: export.limit,
        program: concat!("superloop-chat-export ", env!("CARGO_PKG_VERSION")),
    };
    let outcome = match render_loop(
        export.environment,
        &heads,
        &tree,
        &agents,
        &pages,
        &settings,
    ) {
        Ok(outcome) => outcome,
        Err(RenderError::Foreign(path)) => return refuse(out, &path),
        Err(RenderError::Io(error)) => {
            return Err(Failure::Io(format!(
                "cannot render {name} into {}: {error}",
                output.display()
            )));
        }
    };
    writeln!(
        out,
        "loop={name} {} {} {outcome} wall_ms={}",
        heads.report().with_agents(&agents, skipped_agents.len()),
        Summary::of(&heads, &tree, &agents, &pages),
        started.elapsed().as_millis()
    )
    .map_err(Failure::from)?;
    tell_foreign(name, &output, &outcome);
    Ok(false)
}

fn run(args: Args, out: &mut impl Write) -> Result<(), Failure> {
    let started = Instant::now();
    let Args {
        loops,
        all,
        registry,
        projects,
        chats,
        max_block_bytes,
        dump_plan,
    } = args;
    let registry = home_default(registry, ".local/share/superloop-tools/loops.d")?;
    let projects = home_default(projects, ".claude/projects")?;
    let chats = home_default(chats, "chats")?;
    readable_directory(&registry, "registry")?;
    readable_directory(&projects, "projects")?;
    let registered = read_registry(&registry).map_err(|error| {
        Failure::Io(format!(
            "unreadable registry {}: {error}",
            registry.display()
        ))
    })?;
    let outside: Vec<&String> = registered.keys().filter(|name| !is_segment(name)).collect();
    for name in &outside {
        tell(&format!(
            "left out registered loop {name:?}: a loop's name is one to 64 ASCII letters, digits, '-', '_' or '.', opening with a letter or digit"
        ));
    }
    let names = selected(loops, all, &registered)?;
    std::fs::create_dir_all(&chats).map_err(|error| {
        Failure::Io(format!(
            "unwritable chats directory {}: {error}",
            chats.display()
        ))
    })?;
    let chats_folder = Folder::open(&chats).map_err(|error| {
        Failure::Io(format!(
            "unusable chats directory {}: {error}",
            chats.display()
        ))
    })?;
    let mut dump = dump_plan
        .map(|path| create_dump(&path, &projects, &chats))
        .transpose()?;
    let environment = with_templates().map_err(|error| Failure::Io(error.to_string()))?;
    let export = Export {
        environment: &environment,
        chats: &chats_folder,
        chats_path: &chats,
        projects: &projects,
        limit: usize::try_from(max_block_bytes).unwrap_or(usize::MAX),
    };
    let mut refused = 0;
    for name in &names {
        let slug = project_slug(&registered[name]);
        if export_loop(&export, name, &slug, dump.as_mut(), out)? {
            refused += 1;
        }
    }
    if let Some(dump) = dump.as_mut() {
        dump.flush().map_err(Failure::from)?;
    }
    let listed: Vec<String> = registered.keys().cloned().collect();
    let root = write_loops_index(&environment, &chats_folder, &listed).map_err(|error| {
        Failure::Io(format!(
            "unwritable chats directory {}: {error}",
            chats.display()
        ))
    })?;
    for path in &root.refused {
        tell(&format!(
            "left {:?} in place: it stands where the loops index writes, and the program does not own it",
            chats.join(path).display().to_string()
        ));
    }
    writeln!(
        out,
        "loops={} wall_ms={}",
        names.len(),
        started.elapsed().as_millis()
    )
    .map_err(Failure::from)?;
    if refused > 0 || !root.refused.is_empty() || !outside.is_empty() {
        return Err(Failure::Io(format!(
            "refused {refused} loops, {} files at the output root and {} registered names; see the messages above",
            root.refused.len(),
            outside.len()
        )));
    }
    Ok(())
}

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit("superloop-chat-export", env!("CARGO_PKG_VERSION"), None);
    let args = Args::parse();
    match run(args, &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(message)) => {
            let mut command = Args::command();
            let error = command.error(clap::error::ErrorKind::InvalidValue, message);
            let _ignored = error.print();
            ExitCode::from(2)
        }
        Err(Failure::Io(message)) => {
            tell(&message);
            ExitCode::FAILURE
        }
    }
}
