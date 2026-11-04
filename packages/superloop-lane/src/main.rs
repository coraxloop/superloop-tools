use std::io::{self, Write as _};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;
use std::time::Instant;

use superloop_lane::error::LaneError;
use superloop_lane::{
    build, caller_home, container_helper, home, install, install_door, install_private, launch,
    load_plan, prepare, repair, requests,
};

const USAGE_TEMPLATE: &str = "usage: superloop-lane {bound-roots --runs-root DIR PATH [PATH...]|render-routes --registry FILE --loop LOOP --owner-home PATH --output DIR|gateway {register|deregister|status|check-request|migrate-proposals|serve} ARGS|launch --host LOOP RUN HOST-ARGS...|prepare-signin-home --backend codex LOOP [--charter PATH] [--nodes NAMES] [--reconcile {--dry-run|--expect-digest HEX}]|check-signin-home --backend codex LOOP [--charter PATH] [--nodes NAMES]|driver {start|resume} --backend {claude|codex} ARGS|driver status RUN|driver follow RUN [--save-offset]|prepare LOOP [--dry-run]|plan LOOP RUN|make-home LOOP RUN --letter FILE|launch LOOP RUN {--letter FILE|--round STEP} [--budget SECONDS] [--model MODEL] [--effort EFFORT] [--door-scope {work|review}] [--dry-run] [--expect-digest HEX] [--observe] [--proxy-bin FILE]|launch LOOP RUN --repin-door {--dry-run|--expect-digest HEX}|read-launch-report LOOP RUN [--round STEP]|rewrite-launch-reports LOOP [--dry-run]|settle LOOP RUN --round STEP {--dry-run|--expect-digest HEX}|checkpoint LOOP RUN [--dry-run]|checkout LOOP RUN --repo REPO --into DIR [--dry-run]|harvest LOOP RUN --gate-object HEX [--dry-run]|mark-imported LOOP RUN --object HEX|bind-mail|bind-reply LOOP RUN --step STEP --delivery UTC_INSTANT|follow LOOP RUN [--round STEP] [--round-only]|rotate LOOP RUN [--dry-run] [--expect-digest HEX] [--force REASON] [--next FILE]|census LOOP [--mail-migration]|census rewrite LOOP RUN {--dry-run|--expect-digest HEX}|pause LOOP|resume LOOP|exercise LOOP [--dry-run]|exercise LOOP --run RUN --case {context-use|harvest|run-identity|home-layout|mounts|rotation|resources|reaping|network|door-shape|door-attribution|door-extensions|door-audit|door-allow|door-enforce|door-agent}|network-evidence LOOP RUN < HOST-OBSERVATION.json|retire LOOP RUN [--confirm-uncertain] [--dry-run|--expect-digest HEX]|retire LOOP RUN --node [--dry-run|--expect-digest HEX]|retire LOOP --generations [--dry-run]|retire rewrite-node LOOP {--dry-run|--expect-digest HEX} [--full-plan]|record-hosts LOOP RUN {--list|--host HOST [--host HOST...]} [--dry-run]|build LOOP --base-image REF --codex-bin FILE --codex-host-bin FILE --codex-version VERSION --codex-sha256 HEX --codex-host-sha256 HEX --codex-source URL [--podman-bin FILE] [--template-dir DIR] [--dry-run]|install [--pilot [--refresh-proxy]] LOOP [--dry-run] [--podman-bin FILE] [--data-dir DIR] [--proxy-bin FILE] [--unit-dir DIR]|register-door-node LOOP --alias ALIAS --address ADDRESS --port PORT --user USER --host-key KEY {--dry-run|--expect-digest HEX}|install-door LOOP [--dry-run] [--podman-bin FILE]|door-sign-in LOOP [--dry-run|--expect-digest HEX]|repair LOOP [--dry-run]|requests {<REQUESTS_USAGE>}|--help|--version}\nexercise LOOP --run RUN --case door-attribution requires a started run before settle\nrepin-door: only boxed runs with a registered door can be re-pinned; otherwise repin-door: this run has no door\nsettle: --expect-digest takes the dry run JSON field preview_sha256 (the recorded preview digest)";

static USAGE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    USAGE_TEMPLATE.replace("<REQUESTS_USAGE>", requests::commands::REQUESTS_USAGE)
});

fn print_launch_report(
    mut writer: impl io::Write,
    report: &serde_json::Value,
) -> Result<(), LaneError> {
    writeln!(writer, "{report}").map_err(|error| LaneError::operation("stdout", error.to_string()))
}

fn print_unsaved_launch_report(writer: impl io::Write, report: &serde_json::Value) {
    drop(print_launch_report(writer, report));
}

fn parse_checkpoint_private_argv(
    args: &[String],
) -> Result<(launch::checkpoint::CheckpointRequest, &Path), LaneError> {
    let [_, loop_name, run, home_flag, owner_home, rest @ ..] = args else {
        return Err(LaneError::input(
            "checkpoint-private",
            "private checkpoint form is incomplete",
        ));
    };
    if home_flag != "--owner-home" {
        return Err(LaneError::input(
            "checkpoint-private",
            "private checkpoint form is invalid",
        ));
    }
    let (token, dry_run) = match rest {
        [] => (None, false),
        [dry] if dry == "--dry-run" => (None, true),
        [flag, token] if flag == "--token" => (Some(token.clone()), false),
        [flag, token, dry] if flag == "--token" && dry == "--dry-run" => {
            (Some(token.clone()), true)
        }
        _ => {
            return Err(LaneError::input(
                "checkpoint-private",
                "private checkpoint form is invalid",
            ));
        }
    };
    let mut words = vec![loop_name.clone(), run.clone()];
    if dry_run {
        words.push("--dry-run".to_owned());
    }
    let mut request = launch::checkpoint::CheckpointRequest::parse(&words)?;
    request.invocation_token = token;
    Ok((request, Path::new(owner_home)))
}

fn parse_checkout_private_argv(
    args: &[String],
) -> Result<(launch::checkout::CheckoutRequest, &Path), LaneError> {
    let [
        _,
        loop_name,
        run,
        into_flag,
        into,
        home_flag,
        owner_home,
        repo_flag,
        repo,
        rest @ ..,
    ] = args
    else {
        return Err(LaneError::input(
            "checkout-private",
            "private checkout form is incomplete",
        ));
    };
    if into_flag != "--into" || home_flag != "--owner-home" || repo_flag != "--repo" {
        return Err(LaneError::input(
            "checkout-private",
            "private checkout form is invalid",
        ));
    }
    let mut words = vec![
        loop_name.clone(),
        run.clone(),
        "--repo".into(),
        repo.clone(),
        "--into".into(),
        into.clone(),
    ];
    let token = if rest == ["--dry-run"] {
        words.push("--dry-run".into());
        None
    } else if let [flag, token] = rest
        && flag == "--token"
    {
        Some(token.clone())
    } else {
        return Err(LaneError::input(
            "checkout-private",
            "private checkout form is invalid",
        ));
    };
    let mut request = launch::checkout::CheckoutRequest::parse(&words)?;
    request.invocation_token = token;
    Ok((request, Path::new(owner_home)))
}

fn parse_harvest_private_argv(
    args: &[String],
) -> Result<(launch::harvest::HarvestRequest, &Path, bool), LaneError> {
    let [
        kind,
        loop_name,
        run,
        object_flag,
        object,
        home_flag,
        owner_home,
        rest @ ..,
    ] = args
    else {
        return Err(LaneError::input(
            "harvest-private",
            "private harvest form is incomplete",
        ));
    };
    if (kind != "_harvest" && kind != "_harvest-recover")
        || object_flag != "--gate-object"
        || home_flag != "--owner-home"
    {
        return Err(LaneError::input(
            "harvest-private",
            "private harvest form is invalid",
        ));
    }
    let mut words = vec![
        loop_name.clone(),
        run.clone(),
        object_flag.clone(),
        object.clone(),
    ];
    if rest == ["--dry-run"] {
        words.push("--dry-run".into());
    } else if !rest.is_empty() {
        return Err(LaneError::input(
            "harvest-private",
            "private harvest form is invalid",
        ));
    }
    Ok((
        launch::harvest::HarvestRequest::parse(&words)?,
        Path::new(owner_home),
        kind == "_harvest-recover",
    ))
}

fn parse_import_private_argv(
    args: &[String],
) -> Result<(launch::imports::MarkImportedRequest, &Path), LaneError> {
    let [
        _,
        loop_name,
        run,
        object_flag,
        object,
        home_flag,
        owner_home,
    ] = args
    else {
        return Err(LaneError::input(
            "import-private",
            "private import form is incomplete",
        ));
    };
    if object_flag != "--object" || home_flag != "--owner-home" {
        return Err(LaneError::input(
            "import-private",
            "private import form is invalid",
        ));
    }
    let request = launch::imports::MarkImportedRequest::parse(&[
        loop_name.clone(),
        run.clone(),
        object_flag.clone(),
        object.clone(),
    ])?;
    Ok((request, Path::new(owner_home)))
}

type FollowPrivateForm<'a> = (&'a Path, &'a str, &'a str, &'a str, &'a Path, &'a str);

fn parse_follow_options(rest: &[String]) -> Result<(Option<&str>, bool), LaneError> {
    let (round, round_only) = match rest {
        [] => (None, false),
        [option] if option == "--round-only" => (None, true),
        [option, step] if option == "--round" => (Some(step.as_str()), false),
        [option, step, flag] if option == "--round" && flag == "--round-only" => {
            (Some(step.as_str()), true)
        }
        [flag, option, step] if flag == "--round-only" && option == "--round" => {
            (Some(step.as_str()), true)
        }
        _ => {
            return Err(LaneError::input(
                "follow-usage",
                "follow LOOP RUN [--round STEP] [--round-only]",
            ));
        }
    };
    if let Some(step) = round {
        launch::letters::valid_step(step)?;
    }
    Ok((round, round_only))
}

fn parse_follow_private_argv(args: &[String]) -> Result<FollowPrivateForm<'_>, LaneError> {
    let [
        _,
        loop_name,
        run,
        home_flag,
        owner_home,
        round_flag,
        step,
        directory_flag,
        directory,
        identity_flag,
        identity,
    ] = args
    else {
        return Err(LaneError::input(
            "follow-private",
            "private follow form is incomplete",
        ));
    };
    if home_flag != "--owner-home"
        || round_flag != "--round"
        || directory_flag != "--driver-dir"
        || identity_flag != "--record-identity"
    {
        return Err(LaneError::input(
            "follow-private",
            "private follow form is malformed",
        ));
    }
    Ok((
        Path::new(owner_home),
        loop_name,
        run,
        step,
        Path::new(directory),
        identity,
    ))
}

fn validate_bite_private_argv(args: &[String]) -> Result<(), LaneError> {
    match args.first().map(String::as_str) {
        Some("_checkpoint") => {
            parse_checkpoint_private_argv(args)?;
        }
        Some("_checkout") => {
            parse_checkout_private_argv(args)?;
        }
        Some("_harvest" | "_harvest-recover") => {
            parse_harvest_private_argv(args)?;
        }
        Some("_mark-imported") => {
            parse_import_private_argv(args)?;
        }
        Some("_follow-private") => {
            parse_follow_private_argv(args)?;
        }
        Some("_rotation-handover") => {
            launch::rotation::parse_private_handover_argv(args)?;
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn bind_private_launch_args<'a>(
    args: &'a [String],
    inherited: &impl AsFd,
    owner: u32,
) -> Result<(&'a [String], Option<home::PrivateHomeGuard>), LaneError> {
    let private_launch = matches!(
        args.first().map(String::as_str),
        Some(
            "_choose-uid"
                | "_settle-evidence"
                | "_driver-report"
                | "_exercise-measure"
                | "_exercise-home-layout"
                | "_exercise-harvest"
                | "_exercise-mounts"
                | "_exercise-door-shape"
                | "_exercise-door-attribution"
                | "_exercise-network"
                | "_observed-hosts"
                | "_make-home"
                | "_checkpoint"
                | "_harvest"
                | "_harvest-recover"
                | "_mark-imported"
                | "_checkout"
                | "_bind-mail"
                | "_bind-reply"
                | "_inspect-round"
                | "_follow-private"
                | "_exercise-context-private"
                | "_rotation-handover"
                | "_prepare-runtime"
                | "_container-helper"
        )
    );
    if !private_launch {
        return Ok((args, None));
    }
    let rotation_source = args[0] == "_make-home"
        && args.len() >= 2
        && args[args.len() - 2] == "--verified-letter-source-fd";
    let suffix_len = if rotation_source {
        12
    } else if args[0] == "_make-home" || args[0] == "_checkout" {
        10
    } else {
        6
    };
    let (body, suffix) = args.split_at(args.len().saturating_sub(suffix_len));
    if suffix.len() != suffix_len
        || suffix[0] != "--verified-home-fd"
        || suffix[1] != "0"
        || suffix[2] != "--verified-runs-root"
        || suffix[4] != "--verified-runs-root-fd"
        || (suffix_len >= 10
            && (suffix[6] != "--verified-letter-dir" || suffix[8] != "--verified-letter-fd"))
        || (rotation_source && (suffix[10] != "--verified-letter-source-fd" || suffix[11] != "3"))
    {
        return Err(LaneError::input(
            "verified-prefix",
            "private launch requires bound home, runs root and letter descriptors",
        ));
    }
    if body
        .first()
        .is_some_and(|word| word == "_exercise-home-layout")
    {
        launch::exercise::parse_home_layout_private_argv(body)?;
    }
    if body.first().is_some_and(|word| word == "_exercise-harvest") {
        launch::exercise::parse_harvest_private_argv(body)?;
    }
    if body.first().is_some_and(|word| word == "_exercise-mounts") {
        launch::exercise::mounts::parse_private_argv(body)?;
    }
    if body
        .first()
        .is_some_and(|word| word == "_exercise-door-shape")
    {
        launch::exercise::door_shape::parse_private_argv(body)?;
    }
    if body
        .first()
        .is_some_and(|word| word == "_exercise-door-attribution")
    {
        launch::exercise::door_attribution::parse_private_argv(body)?;
    }
    if body.first().is_some_and(|word| word == "_exercise-network") {
        launch::exercise::network::parse_private_argv(body)?;
    }
    validate_bite_private_argv(body)?;
    let mut homes = body.windows(2).filter(|pair| pair[0] == "--owner-home");
    let owner_home = homes.next().map(|pair| &pair[1]).ok_or_else(|| {
        LaneError::input("verified-prefix", "private launch is missing --owner-home")
    })?;
    if homes.next().is_some() || !Path::new(owner_home).is_absolute() {
        return Err(LaneError::input(
            "verified-prefix",
            "private launch has duplicate or non-absolute owner home",
        ));
    }
    let runs_root = Path::new(&suffix[3]);
    if !runs_root.is_absolute() {
        return Err(LaneError::input(
            "verified-prefix",
            "runs root is not absolute",
        ));
    }
    let descriptor = |word: &str| -> Result<BorrowedFd<'_>, LaneError> {
        let number = word.parse::<i32>().map_err(|_| {
            LaneError::input("verified-prefix", "private descriptor number is invalid")
        })?;
        if number < 3 {
            return Err(LaneError::input(
                "verified-prefix",
                "private descriptor number is invalid",
            ));
        }
        #[allow(unsafe_code)]
        let valid = unsafe { libc::fcntl(number, libc::F_GETFD) };
        if valid < 0 {
            return Err(LaneError::input(
                "verified-prefix",
                "private descriptor is not open",
            ));
        }
        // The private argv names descriptors inherited from the public launch process.
        #[allow(unsafe_code)]
        Ok(unsafe { BorrowedFd::borrow_raw(number) })
    };
    let is_socket = nix::sys::stat::fstat(inherited)
        .map(|stat| {
            nix::sys::stat::SFlag::from_bits_truncate(stat.st_mode)
                .contains(nix::sys::stat::SFlag::S_IFSOCK)
        })
        .map_err(|error| LaneError::input("verified-prefix", error.to_string()))?;
    let transferred = if is_socket {
        if suffix[5] != "1" || (suffix_len >= 10 && suffix[9] != "2") {
            return Err(LaneError::input(
                "verified-prefix",
                "private descriptor transfer index is invalid",
            ));
        }
        Some(home::receive_private_descriptors(
            inherited,
            if rotation_source {
                4
            } else if suffix_len == 10 {
                3
            } else {
                2
            },
        )?)
    } else {
        None
    };
    let runs_direct = if transferred.is_none() {
        Some(
            descriptor(&suffix[5])
                .map_err(|error| LaneError::input("socket-dir-handoff", error.detail))?,
        )
    } else {
        None
    };
    let letter_direct = if suffix_len >= 10 && transferred.is_none() {
        Some(descriptor(&suffix[9])?)
    } else {
        None
    };
    let runs_fd: &dyn AsFd = if let Some(ref fds) = transferred {
        &fds[1]
    } else {
        runs_direct
            .as_ref()
            .ok_or_else(|| LaneError::input("verified-prefix", "runs descriptor absent"))?
    };
    let letter_fd: Option<&dyn AsFd> = if suffix_len >= 10 {
        Some(if let Some(ref fds) = transferred {
            &fds[2]
        } else {
            letter_direct
                .as_ref()
                .ok_or_else(|| LaneError::input("verified-prefix", "letter descriptor absent"))?
        })
    } else {
        None
    };
    let letter_dir = letter_fd.map(|fd| (Path::new(&suffix[7]), fd));
    if let Some((path, _)) = letter_dir {
        let letter_path = Path::new(body.get(4).ok_or_else(|| {
            LaneError::input("verified-prefix", "private launch is missing the letter")
        })?);
        if letter_path.parent() != Some(path) {
            return Err(LaneError::input(
                "verified-prefix",
                "letter directory differs from its bound path",
            ));
        }
    }
    let guard = home::activate_private_launch(
        Path::new(owner_home),
        transferred
            .as_ref()
            .map_or(inherited as &dyn AsFd, |fds| &fds[0] as &dyn AsFd),
        runs_root,
        runs_fd,
        letter_dir,
        owner,
    )?;
    if rotation_source {
        let source = transferred
            .as_ref()
            .and_then(|fds| fds.get(3))
            .ok_or_else(|| LaneError::input("rotate-source", "inherited source is absent"))?;
        home::attach_private_rotation_source(source, owner)?;
    }
    Ok((body, Some(guard)))
}

#[allow(clippy::too_many_lines)]
fn run(args: &[String]) -> Result<i32, LaneError> {
    let (args, _private_home) = bind_private_launch_args(args, &io::stdin(), 0)?;
    if args.first().is_some_and(|word| word == "_container-client") {
        let [_, option, run_dir] = args else {
            return Err(LaneError::input(
                "helper-usage",
                "_container-client --run-dir DIR",
            ));
        };
        if option != "--run-dir" || !Path::new(run_dir).is_absolute() {
            return Err(LaneError::input(
                "helper-usage",
                "_container-client --run-dir DIR",
            ));
        }
        return container_helper::client(Path::new(run_dir));
    }
    if args.first().is_some_and(|word| word == "_container-helper") {
        let [_, option, run_dir, home_option, owner_home] = args else {
            return Err(LaneError::input(
                "helper-usage",
                "_container-helper --run-dir DIR --owner-home HOME",
            ));
        };
        if option != "--run-dir"
            || home_option != "--owner-home"
            || !Path::new(run_dir).is_absolute()
            || !Path::new(owner_home).is_absolute()
        {
            return Err(LaneError::input(
                "helper-usage",
                "_container-helper --run-dir DIR --owner-home HOME",
            ));
        }
        return container_helper::serve(Path::new(run_dir)).map(|()| 0);
    }
    if args == ["--help"] {
        writeln!(io::stdout().lock(), "{}", USAGE.as_str())
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|command| command == "launch")
        && args.iter().any(|word| word == "--repin-door")
    {
        let request = launch::repin_door::Request::parse(&args[1..])?;
        let report = launch::repin_door::run(&caller_home()?, &request)?;
        print_launch_report(io::stdout().lock(), &report)?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "retire")
        && args.get(1).is_some_and(|value| value == "rewrite-node")
    {
        let report = launch::retire::node_rewrite::run(&caller_home()?, &args[2..])?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if let [command, loop_name, run_name, ..] = args
        && matches!(
            command.as_str(),
            "launch"
                | "bind-mail"
                | "bind-reply"
                | "checkpoint"
                | "checkout"
                | "harvest"
                | "mark-imported"
                | "rotate"
                | "retire"
                | "record-hosts"
        )
        && !args.iter().any(|word| word == "--dry-run")
        && launch::reaping::reconciles_before_command(command)
        && !(command == "record-hosts" && args.iter().any(|word| word == "--list"))
        && superloop_lane::valid_run_name(run_name)
    {
        if command == "retire" {
            launch::reaping::reconcile_before_retirement(&caller_home()?, loop_name, run_name)?;
        } else {
            launch::reaping::reconcile_public(&caller_home()?, loop_name, run_name)?;
        }
    }
    if matches!(args.first().map(String::as_str), Some("launch" | "rotate"))
        && !args.iter().any(|word| word == "--dry-run")
    {
        let recovering = if args.first().is_some_and(|word| word == "launch")
            && std::env::var_os("SUPERLOOP_RUN_SCOPE_UNIT").is_none()
        {
            launch::reaping::scope_preflight_with(
                &caller_home()?,
                args,
                launch::reaping::systemctl_show,
            )?
        } else {
            false
        };
        if recovering {
            launch::reaping::permit_interrupted_only();
        } else if std::env::var_os("SUPERLOOP_RUN_SCOPE_UNIT").is_some() {
            let loop_name = args
                .get(1)
                .ok_or_else(|| LaneError::input("run-scope", "loop is absent"))?;
            launch::reaping::current_scope(loop_name)?;
        } else {
            return launch::reaping::run_in_scope(args);
        }
    }
    if args.first().is_some_and(|value| value == "prepare") {
        let [_, loop_name, rest @ ..] = args else {
            return Err(LaneError::input("usage", "prepare LOOP [--dry-run]"));
        };
        if !rest.is_empty() && rest != ["--dry-run"] {
            return Err(LaneError::input("usage", "prepare LOOP [--dry-run]"));
        }
        let report = prepare::run(&caller_home()?, loop_name, !rest.is_empty())?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "build") {
        let request = build::BuildRequest::parse(&args[1..])?;
        let report = build::run(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "install") {
        let request = install::InstallRequest::parse(&args[1..])?;
        let report = install::run(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "door-sign-in") {
        let report = superloop_lane::door_sign_in::run(&caller_home()?, &args[1..])?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "register-door-node")
    {
        let report = superloop_lane::door_node::run(&caller_home()?, &args[1..])?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "install-door") {
        let request = install_door::DoorRequest::parse(&args[1..])?;
        let report = install_door::run(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_install-door-private")
    {
        let report = install_door::run_private_entry(&args[1..], &io::stdin())?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "repair") {
        let request = repair::RepairRequest::parse(&args[1..])?;
        let report = repair::run(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "requests") {
        requests::commands::run(
            &caller_home()?,
            &args[1..],
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
        )?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "launch") {
        let request = launch::LaunchRequest::parse(&args[1..])?;
        let report = launch::run_with_failure_report(&caller_home()?, &request, &mut |unsaved| {
            print_unsaved_launch_report(io::stdout().lock(), unsaved);
        })?;
        print_launch_report(io::stdout().lock(), &report)?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "rewrite-launch-reports")
    {
        let (loop_name, dry_run) = match args {
            [_, name] => (name, false),
            [_, name, flag] if flag == "--dry-run" => (name, true),
            _ => {
                return Err(LaneError::input(
                    "rewrite-launch-reports-usage",
                    "rewrite-launch-reports LOOP [--dry-run]",
                ));
            }
        };
        let report = launch::report::rewrite(&caller_home()?, loop_name, dry_run)?;
        print_launch_report(io::stdout().lock(), &report)?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "read-launch-report")
    {
        let [_, loop_name, run, rest @ ..] = args else {
            return Err(LaneError::input(
                "read-launch-report-usage",
                "read-launch-report LOOP RUN [--round STEP]",
            ));
        };
        let step = match rest {
            [] => None,
            [option, step] if option == "--round" => Some(step.as_str()),
            _ => {
                return Err(LaneError::input(
                    "read-launch-report-usage",
                    "read-launch-report LOOP RUN [--round STEP]",
                ));
            }
        };
        let report = launch::report::read(&caller_home()?, loop_name, run, step)?;
        print_launch_report(io::stdout().lock(), &report)?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "settle") {
        let request = launch::settle::SettleRequest::parse(&args[1..])?;
        let report =
            launch::settle::run_with_failure_report(&caller_home()?, &request, &mut |unsaved| {
                print_unsaved_launch_report(io::stdout().lock(), unsaved);
            })?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| matches!(value.as_str(), "bind-mail" | "bind-reply"))
    {
        let request = launch::steering::Request::parse(&args[1..])?;
        let report = launch::steering::run(&caller_home()?, &request, args[0] == "bind-reply")?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }

    if args.first().is_some_and(|value| value == "follow") {
        let [_, loop_name, run, rest @ ..] = args else {
            return Err(LaneError::input(
                "follow-usage",
                "follow LOOP RUN [--round STEP] [--round-only]",
            ));
        };
        let (round, round_only) = parse_follow_options(rest)?;
        launch::follow::run(
            &caller_home()?,
            loop_name,
            run,
            round,
            round_only,
            &mut io::stdout().lock(),
        )?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "rotate") {
        let request = launch::rotation::RotateRequest::parse(&args[1..])?;
        let report = launch::rotation::run(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_rotation-handover")
    {
        let (loop_name, run, owner_home, runs_root, record_identity) =
            launch::rotation::parse_private_handover_argv(args)?;
        let report = launch::rotation::private_handover(
            owner_home,
            loop_name,
            run,
            runs_root,
            record_identity,
        )?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "_follow-private") {
        let (owner_home, loop_name, run, step, directory, identity) =
            parse_follow_private_argv(args)?;
        let lines =
            launch::follow::private_read(owner_home, loop_name, run, step, directory, identity)?;
        io::stdout()
            .lock()
            .write_all(lines.as_bytes())
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_exercise-context-private")
    {
        let [
            _,
            loop_name,
            run,
            home_option,
            owner_home,
            round_option,
            step,
            directory_option,
            directory,
            identity_option,
            identity,
        ] = args
        else {
            return Err(LaneError::input(
                "exercise-context",
                "private context form is incomplete",
            ));
        };
        if home_option != "--owner-home"
            || round_option != "--round"
            || directory_option != "--driver-dir"
            || identity_option != "--record-identity"
        {
            return Err(LaneError::input(
                "exercise-context",
                "private context form is malformed",
            ));
        }
        let report = launch::follow::private_context(
            Path::new(owner_home),
            loop_name,
            run,
            step,
            Path::new(directory),
            identity,
        )?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "census") {
        if args.get(1).is_some_and(|value| value == "rewrite") {
            let report = launch::census::rewrite::run(&caller_home()?, &args[2..])?;
            writeln!(io::stdout().lock(), "{report}")
                .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
            return Ok(0);
        }
        let report = match args {
            [_, loop_name] => launch::census::run(&caller_home()?, loop_name)?,
            [_, loop_name, mode] if mode == "--mail-migration" => {
                launch::census::mail_migration(&caller_home()?, loop_name)?
            }
            _ => {
                return Err(LaneError::input(
                    "census-usage",
                    "census LOOP [--mail-migration]",
                ));
            }
        };
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "network-evidence")
    {
        let mut input = io::stdin().lock();
        let report = launch::network_evidence::run(&caller_home()?, args, &mut input)?;
        drop(input);
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "exercise") {
        let [_, loop_name, rest @ ..] = args else {
            return Err(LaneError::input(
                "exercise-usage",
                "exercise LOOP [--dry-run]",
            ));
        };
        if let [run_flag, run, case_flag, case] = rest
            && run_flag == "--run"
            && case_flag == "--case"
        {
            let report = launch::exercise::run_case(&caller_home()?, loop_name, run, case)?;
            let status = launch::exercise::case_status(&report)?;
            writeln!(io::stdout().lock(), "{report}")
                .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
            return Ok(status);
        }
        let dry_run = match rest {
            [] => false,
            [flag] if flag == "--dry-run" => true,
            _ => {
                return Err(LaneError::input(
                    "exercise-usage",
                    "exercise LOOP [--dry-run]",
                ));
            }
        };
        let report = launch::exercise::run(&caller_home()?, loop_name, dry_run)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "pause" || value == "resume")
    {
        let [command, loop_name] = args else {
            return Err(LaneError::input(
                "admission-usage",
                "pause LOOP or resume LOOP",
            ));
        };
        let report = launch::admission::set(&caller_home()?, loop_name, command == "pause")?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "retire") {
        let request = launch::retire::RetireRequest::parse(&args[1..])?;
        let report = launch::retire::run(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "checkpoint") {
        let request = launch::checkpoint::CheckpointRequest::parse(&args[1..])?;
        let report = launch::checkpoint::run(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "checkout") {
        let request = launch::checkout::CheckoutRequest::parse(&args[1..])?;
        let report = launch::checkout::run(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "mark-imported") {
        let request = launch::imports::MarkImportedRequest::parse(&args[1..])?;
        let report = launch::imports::run(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "harvest") {
        let request = launch::harvest::HarvestRequest::parse(&args[1..])?;
        let report = launch::harvest::run(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_harvest" || value == "_harvest-recover")
    {
        let (request, owner_home, recovery) = parse_harvest_private_argv(args)?;
        let report = if recovery {
            launch::harvest::private_recover(owner_home, &request)?
        } else {
            launch::harvest::private_run(owner_home, &request)?
        };
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "_mark-imported") {
        let (request, owner_home) = parse_import_private_argv(args)?;
        let report = launch::imports::private_run(owner_home, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "_checkpoint") {
        let (request, owner_home) = parse_checkpoint_private_argv(args)?;
        let report = launch::checkpoint::private_run(owner_home, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "_checkout") {
        let (request, owner_home) = parse_checkout_private_argv(args)?;
        let report = launch::checkout::private_run(owner_home, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "record-hosts") {
        let request = launch::RecordHostsRequest::parse(&args[1..])?;
        let report = launch::record_hosts(&caller_home()?, &request)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "_choose-uid") {
        let [_, loop_name, run, option, owner_home] = args else {
            return Err(LaneError::input(
                "uid-private",
                "private UID query is incomplete",
            ));
        };
        if option != "--owner-home" || !nix::unistd::Uid::effective().is_root() {
            return Err(LaneError::input(
                "uid-private",
                "rootless namespace root and --owner-home are required",
            ));
        }
        let uid = launch::choose_worker_uid(Path::new(owner_home), loop_name, run)?;
        writeln!(io::stdout().lock(), "{uid}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "_driver-report") {
        let report = launch::driver_report::private(args)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_settle-evidence")
    {
        if let [
            _,
            loop_name,
            run,
            option,
            owner_home,
            round_flag,
            step,
            rest @ ..,
        ] = args
            && option == "--owner-home"
            && round_flag == "--round"
        {
            let mut words = vec![
                loop_name.clone(),
                run.clone(),
                round_flag.clone(),
                step.clone(),
            ];
            words.extend_from_slice(rest);
            let request = launch::settle::SettleRequest::parse(&words)?;
            let report = launch::settle::private_recover(Path::new(owner_home), &request)?;
            writeln!(io::stdout().lock(), "{report}")
                .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
            return Ok(0);
        }
        let [_, loop_name, run, option, owner_home] = args else {
            return Err(LaneError::input(
                "settle-private",
                "private evidence form is incomplete",
            ));
        };
        if option != "--owner-home" {
            return Err(LaneError::input(
                "settle-private",
                "private evidence needs --owner-home",
            ));
        }
        let report = launch::private_settle(Path::new(owner_home), loop_name, run)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_exercise-measure")
    {
        let [_, loop_name, run, option, owner_home] = args else {
            return Err(LaneError::input(
                "exercise-private",
                "private exercise form is incomplete",
            ));
        };
        if run != "all" || option != "--owner-home" {
            return Err(LaneError::input(
                "exercise-private",
                "private exercise needs all and --owner-home",
            ));
        }
        let report = launch::exercise::private_measure(Path::new(owner_home), loop_name)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_exercise-home-layout")
    {
        let (loop_name, run, expected_record, owner_home) =
            launch::exercise::parse_home_layout_private_argv(args)?;
        let report =
            launch::exercise::private_home_layout(owner_home, loop_name, run, expected_record)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_exercise-harvest")
    {
        let (loop_name, run, expected_record, owner_home) =
            launch::exercise::parse_harvest_private_argv(args)?;
        let report =
            launch::exercise::private_harvest_audit(owner_home, loop_name, run, expected_record)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_exercise-mounts")
    {
        let (loop_name, run, expected_record, owner_home) =
            launch::exercise::mounts::parse_private_argv(args)?;
        let report =
            launch::exercise::mounts::private_measure(owner_home, loop_name, run, expected_record)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_exercise-door-shape")
    {
        let (loop_name, run, expected_record, owner_home) =
            launch::exercise::door_shape::parse_private_argv(args)?;
        let report = launch::exercise::door_shape::private_measure(
            owner_home,
            loop_name,
            run,
            expected_record,
        )?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_exercise-door-attribution")
    {
        let (loop_name, run, expected_record, owner_home) =
            launch::exercise::door_attribution::parse_private_argv(args)?;
        let report = launch::exercise::door_attribution::private_measure(
            owner_home,
            loop_name,
            run,
            expected_record,
        )?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_exercise-network")
    {
        let (loop_name, run, expected_record, owner_home) =
            launch::exercise::network::parse_private_argv(args)?;
        let report = launch::exercise::network::private_measure(
            owner_home,
            loop_name,
            run,
            expected_record,
        )?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_exercise-layout-canary")
    {
        let [_, directory, worker, group] = args else {
            return Err(LaneError::input(
                "exercise-layout-canary",
                "canary form is incomplete",
            ));
        };
        let worker = worker
            .parse::<u32>()
            .map_err(|error| LaneError::input("exercise-layout-canary", error.to_string()))?;
        let group = group
            .parse::<u32>()
            .map_err(|error| LaneError::input("exercise-layout-canary", error.to_string()))?;
        let report = launch::exercise::worker_layout_canary(directory, worker, group)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "_observed-hosts") {
        let [_, loop_name, run, option, owner_home] = args else {
            return Err(LaneError::input(
                "hosts-private",
                "private observation form is incomplete",
            ));
        };
        if option != "--owner-home" {
            return Err(LaneError::input(
                "hosts-private",
                "private observation needs --owner-home",
            ));
        }
        let report = launch::private_observed_hosts(Path::new(owner_home), loop_name, run)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "_make-home") {
        let [
            _,
            loop_name,
            run,
            letter_option,
            letter,
            home_option,
            owner_home,
            uid_option,
            worker_uid,
            podman_option,
            podman,
            model_option,
            model,
            effort_option,
            effort,
            model_source_option,
            model_source,
            effort_source_option,
            effort_source,
            door_scope_option,
            door_scope,
            rest @ ..,
        ] = args
        else {
            return Err(LaneError::input(
                "make-home-private",
                "private home form is incomplete",
            ));
        };
        let (rotation_digest, observe) = match rest {
            [] => (None, false),
            [option] if option == "--observe" => (None, true),
            [option, digest] if option == "--rotation-sha256" => (Some(digest.as_str()), false),
            [option, digest, observe]
                if option == "--rotation-sha256" && observe == "--observe" =>
            {
                (Some(digest.as_str()), true)
            }
            _ => {
                return Err(LaneError::input(
                    "make-home-private",
                    "private home form has unexpected arguments",
                ));
            }
        };
        if letter_option != "--letter"
            || home_option != "--owner-home"
            || uid_option != "--worker-uid"
            || podman_option != "--podman-bin"
            || model_option != "--model"
            || effort_option != "--effort"
            || model_source_option != "--model-source"
            || effort_source_option != "--effort-source"
            || door_scope_option != "--door-scope"
        {
            return Err(LaneError::input(
                "make-home-private",
                "private home form has unexpected arguments",
            ));
        }
        let report = launch::private_make(
            Path::new(owner_home),
            loop_name,
            run,
            Path::new(letter),
            observe,
            worker_uid
                .parse()
                .map_err(|_| LaneError::input("make-home-private", "worker UID is not decimal"))?,
            Path::new(podman),
            &serde_json::json!({"model":model,"effort":effort,"model_source":model_source,"effort_source":effort_source}),
            rotation_digest,
            match door_scope.as_str() {
                "work" => superloop_lane::door::Scope::Work,
                "review" => superloop_lane::door::Scope::Review,
                _ => {
                    return Err(LaneError::input(
                        "make-home-private",
                        "door scope is invalid",
                    ));
                }
            },
        )?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| matches!(value.as_str(), "_bind-mail" | "_bind-reply"))
    {
        let [
            _,
            loop_name,
            run,
            home_flag,
            owner_home,
            step_flag,
            step,
            delivery_flag,
            delivery,
            rest @ ..,
        ] = args
        else {
            return Err(LaneError::input(
                "mail-private",
                "private delivery binding form is incomplete",
            ));
        };
        if home_flag != "--owner-home" || step_flag != "--step" || delivery_flag != "--delivery" {
            return Err(LaneError::input(
                "mail-private",
                "private delivery binding options differ",
            ));
        }
        let verify_only = match rest {
            [] => false,
            [flag] if flag == "--verify-only" && args[0] == "_bind-mail" => true,
            _ => {
                return Err(LaneError::input(
                    "mail-private",
                    "private delivery binding options differ",
                ));
            }
        };
        let report = launch::steering::private_bind(
            Path::new(owner_home),
            loop_name,
            run,
            step,
            delivery,
            args[0] == "_bind-reply",
            verify_only,
        )?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "_inspect-round") {
        let [_, loop_name, run, option, owner_home, rest @ ..] = args else {
            return Err(LaneError::input(
                "round-private",
                "private round inspection is incomplete",
            ));
        };
        if option != "--owner-home" {
            return Err(LaneError::input(
                "round-private",
                "private round inspection needs --owner-home",
            ));
        }
        let evidence = match rest {
            [] => None,
            [record_option, step, budget_option, seconds]
                if record_option == "--record" && budget_option == "--budget" =>
            {
                Some((
                    step.as_str(),
                    seconds
                        .parse::<u64>()
                        .map_err(|_| LaneError::input("round-private", "budget is malformed"))?,
                ))
            }
            _ => {
                return Err(LaneError::input(
                    "round-private",
                    "private round evidence form is malformed",
                ));
            }
        };
        let report =
            launch::rounds::private_inspect(Path::new(owner_home), loop_name, run, evidence)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_prepare-runtime")
    {
        let [_, loop_name, run, home_option, owner_home, option, podman] = args else {
            return Err(LaneError::input(
                "runtime-private",
                "private runtime form is incomplete",
            ));
        };
        if option != "--podman-bin" || home_option != "--owner-home" {
            return Err(LaneError::input(
                "runtime-private",
                "private runtime needs --podman-bin and --owner-home",
            ));
        }
        let report = launch::private_prepare_runtime(
            Path::new(owner_home),
            loop_name,
            run,
            Path::new(podman),
        )?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    if args.first().is_some_and(|value| value == "_proxy") {
        return install::run_proxy(&caller_home()?, &args[1..]).map(|()| 0);
    }
    if args
        .first()
        .is_some_and(|value| value == "_install-private")
    {
        let private = install_private::PrivateRequest::parse(&args[1..])?;
        if !nix::unistd::Uid::effective().is_root() {
            return Err(LaneError::input(
                "install-private",
                "rootless namespace root is required",
            ));
        }
        let loop_name = private.loop_name;
        let owner_home = private.owner_home;
        let data_dir = private.data_dir;
        let codex_bin = private.codex_bin;
        let codex_host_bin = private.codex_host_bin;
        let image_digest = private.image_digest;
        let codex_sha256 = private.codex_sha256;
        let tools_commit = private.tools_commit;
        let mut transferred = home::receive_private_descriptors(&io::stdin(), 2)?;
        let lock_descriptor = transferred
            .pop()
            .ok_or_else(|| LaneError::input("install-lock", "install-lock descriptor is absent"))?;
        let home_descriptor = transferred.pop().ok_or_else(|| {
            LaneError::input("verified-prefix", "owner-home descriptor is absent")
        })?;
        let _verified_home = home::bind_private_home(owner_home, &home_descriptor, 0)?;
        let loop_config = owner_home.join(".config/loops").join(loop_name);
        let install_guard = install::InstallGuard::from_handed_mode(
            &loop_config,
            owner_home,
            0,
            lock_descriptor,
            private.shared_lock,
        )?;
        let configuration_root = owner_home.join(".config/loops");
        let pinned_configuration = home::pin_parent_beneath(&configuration_root, owner_home, 0)?;
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("loop-name", error.message()))?;
        let registry_path = loop_home::registry_path(
            std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
            owner_home,
        );
        let registry = loop_home::load_registry(&registry_path)
            .map_err(|error| LaneError::input("registry-row", error.message()))?;
        let row = registry
            .row(loop_name, owner_home)
            .map_err(|error| LaneError::input("registry-row", error.message()))?;
        let worker_block = loop_home::allocations::Allocations::read_beneath(
            &loop_home::allocations::allocations_path(owner_home),
            &configuration_root,
            &pinned_configuration,
        )
        .and_then(|allocations| allocations.require(loop_name))
        .map_err(|error| LaneError::input("allocations", error.message()))?;
        let settings_path = owner_home
            .join(".config/loops")
            .join(loop_name)
            .join("workers.toml");
        let settings =
            superloop_lane::settings::Settings::read_beneath(&settings_path, owner_home)?;
        settings.validate_grant(owner_home, loop_name)?;
        if settings.image_digest.as_deref() != Some(image_digest)
            && !(private.repair && private.dry_run)
        {
            return Err(LaneError::input(
                "install-private",
                "image ID differs from workers.toml",
            ));
        }
        let report_path = settings_path.with_file_name("image-build.json");
        let built: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report_path).map_err(|error| {
                LaneError::input(
                    "build-report",
                    format!("{}: {error}", report_path.display()),
                )
            })?)
            .map_err(|error| {
                LaneError::input(
                    "build-report",
                    format!("{}: {error}", report_path.display()),
                )
            })?;
        let payloads = superloop_lane::build::payload::install_payloads(&built, &settings)?;
        let codex = payloads
            .iter()
            .find(|payload| payload.vendor == superloop_lane::build::payload::CODEX);
        let expected_codex =
            codex.map_or_else(|| std::path::Path::new(""), |payload| payload.bin.as_path());
        let expected_host = codex
            .and_then(|payload| payload.companion.as_ref())
            .map_or_else(|| std::path::Path::new(""), |(path, _)| path.as_path());
        if built["image_digest"] != *image_digest
            || built["tools_commit"] != *tools_commit
            || codex_bin != expected_codex
            || codex_host_bin != expected_host
            || codex_sha256 != codex.map_or("", |payload| payload.sha256.as_str())
        {
            return Err(LaneError::input(
                "install-private",
                "private inputs differ from image-build.json",
            ));
        }
        for payload in &payloads {
            if superloop_lane::build::sha256(&payload.bin)? != payload.sha256 {
                return Err(LaneError::input(
                    "install-private",
                    "private program differs from image-build.json",
                ));
            }
            if let Some((path, hash)) = &payload.companion
                && superloop_lane::build::sha256(path)? != *hash
            {
                return Err(LaneError::input(
                    "install-private",
                    "private companion differs from image-build.json",
                ));
            }
        }
        let mut report = install_private::run_payloads(
            owner_home,
            loop_name,
            row.uid,
            (0, 0),
            data_dir,
            &payloads,
            image_digest,
            tools_commit,
            private.expected_source,
            private.dry_run,
            private.repair,
            &install_guard,
        )?;
        let sign_in = if settings.configures("codex") {
            superloop_lane::sign_in::converge(
                owner_home,
                loop_name,
                0,
                row.uid,
                worker_block.base,
                private.dry_run,
            )?
        } else {
            serde_json::json!({"changes":[],"applicable":false})
        };
        if let Some(destinations) = report
            .get_mut("destinations")
            .and_then(serde_json::Value::as_array_mut)
        {
            let sign_in_path = owner_home
                .join(".config/loops")
                .join(loop_name)
                .join("lanes/codex");
            for destination in destinations {
                if destination["path"] == sign_in_path.display().to_string() {
                    destination["was_converged"] = sign_in["was_complete"].clone();
                    destination["convergence_complete"] = sign_in["complete"].clone();
                    destination["complete"] = sign_in["complete"].clone();
                }
            }
        }
        let report = install_private::with_sign_in(report, sign_in)?;
        writeln!(io::stdout().lock(), "{report}")
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    let (command, loop_name, run, letter) = match args {
        [command, loop_name, run] if command == "plan" => {
            (command.as_str(), loop_name.as_str(), run.as_str(), None)
        }
        [command, loop_name, run, option, path]
            if command == "make-home" && option == "--letter" =>
        {
            (
                command.as_str(),
                loop_name.as_str(),
                run.as_str(),
                Some(path.as_str()),
            )
        }
        _ => return Err(LaneError::input("usage", USAGE.as_str())),
    };
    let caller = (
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
    );
    let (plan, settings) = load_plan(&caller_home()?, loop_name, run, caller)?;
    if command == "plan" {
        writeln!(io::stdout().lock(), "{}", plan.json()?)
            .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
        return Ok(0);
    }
    let letter_path = Path::new(letter.unwrap_or_default());
    let bytes = home::read_letter(letter_path, caller.0)?;
    let report = home::make_home(&plan, &settings, &bytes, caller)?;
    writeln!(io::stdout().lock(), "{report}")
        .map_err(|error| LaneError::operation("stdout", error.to_string()))?;
    Ok(0)
}

fn main() -> std::process::ExitCode {
    superloop_cli_common::version_or_exit(
        "superloop-lane",
        env!("CARGO_PKG_VERSION"),
        option_env!("SUPERLOOP_TOOLS_COMMIT"),
    );
    let raw = std::env::args_os().skip(1).collect::<Vec<_>>();
    if raw.first().is_some_and(|argument| {
        argument == "_mail-worker-birth"
            || argument == "_mail-worker-state"
            || argument == "_mail-worker-pins"
    }) {
        return std::process::ExitCode::from(loop_home::mail::worker_provision::entry(
            &raw,
            &mut std::io::stderr().lock(),
        ));
    }
    if raw.first().is_some_and(|word| word == "bound-roots") {
        return launch::bound_roots::command(&raw[1..]);
    }
    if raw.first().is_some_and(|word| word == "render-routes") {
        return superloop_lane::routes::command(&raw[1..]);
    }
    if raw.first().is_some_and(|word| word == "launch")
        && raw.get(1).is_some_and(|word| word == "--host")
    {
        return superloop_lane::worker_launch::command(&raw[2..]);
    }
    if raw.first().is_some_and(|word| word == "gateway") {
        return superloop_lane::gateway_dispatch::command(&raw[1..]);
    }
    if raw.first().is_some_and(|word| word == "driver") {
        return superloop_lane::driver::command(&raw[1..]);
    }
    if let Some(command) = raw.first().and_then(|word| word.to_str())
        && matches!(command, "prepare-signin-home" | "check-signin-home")
    {
        let Ok(args) = raw[1..]
            .iter()
            .cloned()
            .map(std::ffi::OsString::into_string)
            .collect::<Result<Vec<_>, _>>()
        else {
            return std::process::ExitCode::from(2);
        };
        return std::process::ExitCode::from(superloop_lane::signin_home::command(
            &args,
            command == "check-signin-home",
        ));
    }
    let started = Instant::now();
    if let Err(error) = launch::reaping::announce_scope_start() {
        let _written = writeln!(
            io::stderr().lock(),
            "{}",
            refusal_line(&error, started.elapsed().as_secs_f64())
        );
        return std::process::ExitCode::from(error.status);
    }
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(status) => std::process::ExitCode::from(u8::try_from(status).unwrap_or(1)),
        Err(error) => {
            let _written = writeln!(
                io::stderr().lock(),
                "{}",
                refusal_line(&error, started.elapsed().as_secs_f64())
            );
            std::process::ExitCode::from(error.status)
        }
    }
}

fn refusal_line(error: &LaneError, wall_seconds: f64) -> String {
    format!("{} wall_seconds={wall_seconds:.6}", error.line())
}

#[cfg(test)]
mod tests {
    use super::{
        USAGE, bind_private_launch_args, parse_follow_options, print_launch_report,
        print_unsaved_launch_report, refusal_line, run,
    };
    use std::fs;
    use std::io::{self, Write};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixStream;
    use superloop_lane::error::LaneError;

    struct BrokenOutput;

    /// ´test:unit:launch-repin-form-is-listed-and-dispatched-before-scope-entry´
    #[test]
    fn launch_repin_form_is_listed_and_dispatched_before_scope_entry() {
        assert!(
            super::USAGE.contains("launch LOOP RUN --repin-door {--dry-run|--expect-digest HEX}")
        );
        assert!(super::USAGE.contains("repin-door: this run has no door"));
        for words in [
            vec!["launch", "alpha", "R", "--repin-door"],
            vec![
                "launch",
                "alpha",
                "R",
                "--repin-door",
                "--dry-run",
                "--round",
                "work",
            ],
            vec![
                "launch",
                "alpha",
                "R",
                "--repin-door",
                "--expect-digest",
                "bad",
            ],
        ] {
            let error = super::run(&words.into_iter().map(String::from).collect::<Vec<_>>())
                .expect_err("invalid host-only form");
            assert_eq!(error.kind, "usage");
            assert!(error.detail.contains("--repin-door"));
        }
    }

    /// ´test:unit:follow-options-accept-five-forms-and-refuse-bad-forms´
    #[test]
    fn follow_options_accept_five_forms_and_refuse_bad_forms() {
        let cases: [(&[&str], Option<&str>, bool); 5] = [
            (&[], None, false),
            (&["--round-only"], None, true),
            (&["--round", "S"], Some("S"), false),
            (&["--round", "S", "--round-only"], Some("S"), true),
            (&["--round-only", "--round", "S"], Some("S"), true),
        ];
        for (words, expected_round, expected_only) in cases {
            let args: Vec<_> = words.iter().map(|word| (*word).to_owned()).collect();
            assert_eq!(
                parse_follow_options(&args).expect("accepted follow form"),
                (expected_round, expected_only)
            );
        }
        for words in [
            ["--round"].as_slice(),
            ["--round-only", "--round"].as_slice(),
        ] {
            let args: Vec<_> = words.iter().map(|word| (*word).to_owned()).collect();
            assert_eq!(
                parse_follow_options(&args).expect_err("missing step").kind,
                "follow-usage"
            );
        }
        let args = ["--round", "bad/step"].map(str::to_owned);
        assert_eq!(
            parse_follow_options(&args).expect_err("invalid step").kind,
            "round-step"
        );
    }

    impl Write for BrokenOutput {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// ´test:unit:launch-print-broken-pipe-names-stdout´
    #[test]
    fn launch_print_broken_pipe_names_stdout() {
        let report = serde_json::json!({"schema":1,"command":"launch","dry_run":false});
        let refusal = print_launch_report(BrokenOutput, &report).expect_err("stdout closed");
        assert_eq!(refusal.kind, "stdout");
    }

    /// ´test:unit:unsaved-report-writer-prints-when-open-and-ignores-closed-pipe´
    #[test]
    fn unsaved_report_writer_prints_when_open_and_ignores_closed_pipe() {
        let report = serde_json::json!({"schema":1,"command":"launch","dry_run":false});
        let mut output = Vec::new();
        print_unsaved_launch_report(&mut output, &report);
        assert_eq!(output, format!("{report}\n").as_bytes());
        print_unsaved_launch_report(BrokenOutput, &report);
    }

    /// ´test:unit:install-private-entry-requires-namespace-root-before-descriptors´
    #[test]
    fn install_private_entry_requires_namespace_root_before_descriptors() {
        let args = [
            "_install-private",
            "alpha",
            "~/owner",
            "~/data",
            "~/codex",
            "~/codex-host",
            "digest",
            "sha256",
            "commit",
            "--dry-run",
            "--verified-home-fd",
            "0",
            "--verified-install-lock-fd",
            "1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let refusal = run(&args).expect_err("host uid refuses before descriptor receive");
        assert_eq!(refusal.kind, "install-private");
        assert_eq!(refusal.detail, "rootless namespace root is required");
    }

    /// ´test:unit:install-door-entry-requires-namespace-root´
    #[test]
    #[allow(
        unsafe_code,
        clippy::borrow_as_ptr,
        clippy::cast_possible_truncation,
        clippy::too_many_lines
    )]
    fn install_door_entry_requires_namespace_root() {
        let malformed = vec!["_install-door-private".into(), "alpha".into()];
        let error = run(&malformed).expect_err("malformed private entry");
        assert_eq!(error.kind, "install-door-private");
        assert_eq!(error.detail, "private form is incomplete");

        let fixture = tempfile::tempdir().expect("fixture");
        let home = fixture.path();
        let owner = nix::unistd::Uid::effective().as_raw();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
        for path in [
            home.join(".config"),
            home.join(".config/loops"),
            home.join(".config/loops/alpha"),
            home.join(".var"),
            home.join(".var/loops"),
            home.join(".var/loops/alpha"),
            home.join(".var/loops/alpha/runner-templates"),
            home.join(".var/loops/alpha/runner-templates/codex"),
            home.join(".var/loops/alpha/runner-templates/codex/pin"),
            home.join(".var/loops/alpha/runner-templates/codex/pin/libexec"),
            home.join(".var/loops/alpha/sockets"),
        ] {
            fs::create_dir(&path).expect("directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("directory mode");
        }
        let libexec_path = home.join(".var/loops/alpha/runner-templates/codex/pin/libexec");
        fs::set_permissions(&libexec_path, fs::Permissions::from_mode(0o550))
            .expect("libexec mode");
        fs::write(
            home.join(".config/loops/registry.toml"),
            b"namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"src\" }]\n",
        )
        .expect("registry");
        fs::set_permissions(
            home.join(".config/loops/registry.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("registry mode");
        fs::write(
            home.join(".config/loops/alpha/workers.toml"),
            format!(
                "template_dir = \"{}\"\nsocket_dir = \"{}\"\n",
                home.join(".var/loops/alpha/runner-templates/codex/pin")
                    .display(),
                home.join(".var/loops/alpha/sockets").display()
            ),
        )
        .expect("settings");
        fs::set_permissions(
            home.join(".config/loops/alpha/workers.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("settings mode");
        let source_path = home.join("stub");
        fs::write(&source_path, b"stub").expect("source");
        let digest = superloop_lane::build::sha256(&source_path).expect("stub digest");
        let home_fd = fs::File::open(home).expect("home fd");
        let lock_fd = fs::File::open(home.join(".config/loops/alpha")).expect("lock fd");
        let source_fd = fs::File::open(&source_path).expect("source fd");
        let template_fd = fs::File::open(home.join(".var/loops/alpha/runner-templates/codex/pin"))
            .expect("template fd");
        let libexec_fd =
            fs::File::open(home.join(".var/loops/alpha/runner-templates/codex/pin/libexec"))
                .expect("libexec fd");
        let sockets_fd =
            fs::File::open(home.join(".var/loops/alpha/sockets")).expect("socket root fd");
        let (sender, receiver) = UnixStream::pair().expect("socket pair");
        let fds = [
            home_fd.as_raw_fd(),
            lock_fd.as_raw_fd(),
            source_fd.as_raw_fd(),
            template_fd.as_raw_fd(),
            libexec_fd.as_raw_fd(),
            sockets_fd.as_raw_fd(),
        ];
        let mut byte = [1_u8];
        let mut data = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = [0_usize; 16];
        // SAFETY: the control buffer has space for the six live fixture descriptors.
        unsafe {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &mut data;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen =
                libc::CMSG_SPACE((fds.len() * std::mem::size_of::<libc::c_int>()) as u32) as usize;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN((fds.len() * std::mem::size_of::<libc::c_int>()) as u32) as usize;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
            assert_eq!(
                libc::sendmsg(sender.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                1
            );
        }
        let args = vec![
            "alpha".into(),
            home.display().to_string(),
            source_path.display().to_string(),
            "41001".into(),
            digest,
            "-".into(),
            "preview".into(),
            "--verified-home-fd".into(),
            "0".into(),
            "--verified-install-lock-fd".into(),
            "1".into(),
            "--verified-stub-fd".into(),
            "2".into(),
            "--verified-template-fd".into(),
            "3".into(),
            "--verified-libexec-fd".into(),
            "4".into(),
            "--verified-socket-root-fd".into(),
            "5".into(),
        ];
        for (index, value) in [
            (0, "BAD"),
            (3, "uid"),
            (4, "digest"),
            (6, "unknown"),
            (7, "--wrong"),
            (12, "3"),
            (13, "--wrong"),
            (14, "4"),
            (15, "--wrong"),
            (16, "5"),
            (17, "--wrong"),
            (18, "6"),
        ] {
            let mut malformed = vec!["_install-door-private".into()];
            let mut changed = args.clone();
            changed[index] = value.into();
            malformed.extend(changed);
            let error = run(&malformed).expect_err("private form refuses before transfer");
            assert_eq!(error.kind, "install-door-private");
        }
        let refusal = superloop_lane::install_door::run_private_entry(&args, &receiver)
            .expect_err("host uid cannot claim namespace root");
        assert_eq!(refusal.kind, "install-door-private");
        assert_eq!(refusal.detail, "rootless namespace root is required");
        drop(lock_fd);
        let _handed = superloop_lane::home::activate_handed_home(home, &home_fd, owner)
            .expect("activate handed home without root walk");
        let wrong_lock: std::os::fd::OwnedFd = fs::File::open(home).expect("wrong lock").into();
        let error = superloop_lane::install::InstallGuard::from_handed(
            &home.join(".config/loops/alpha"),
            home,
            owner,
            wrong_lock,
        )
        .expect_err("changed handed lock");
        assert_eq!(error.kind, "install-lock");
        let lock_path = home.join(".config/loops/alpha");
        let first_lock: std::os::fd::OwnedFd = fs::File::open(&lock_path)
            .expect("first lock descriptor")
            .into();
        let _held_lock =
            superloop_lane::install::InstallGuard::from_handed(&lock_path, home, owner, first_lock)
                .expect("first handed lock");
        let second_lock: std::os::fd::OwnedFd = fs::File::open(&lock_path)
            .expect("second lock descriptor")
            .into();
        let busy = superloop_lane::install::InstallGuard::from_handed(
            &lock_path,
            home,
            owner,
            second_lock,
        )
        .expect_err("second independent lock is busy");
        assert_eq!(busy.kind, "install-lock");
        let (closed_sender, missing_transfer) = UnixStream::pair().expect("missing transfer pair");
        drop(closed_sender);
        let error = superloop_lane::install_door::run_private_entry(&args, &missing_transfer)
            .expect_err("host uid still refuses before transfer");
        assert_eq!(error.detail, "rootless namespace root is required");
    }

    /// ´test:unit:usage-names-the-digest-matched-proxy-override´
    #[test]
    fn usage_names_the_digest_matched_proxy_override() {
        assert!(
            USAGE.contains(
                "launch LOOP RUN {--letter FILE|--round STEP} [--budget SECONDS] [--model MODEL] [--effort EFFORT] [--door-scope {work|review}] [--dry-run] [--expect-digest HEX] [--observe] [--proxy-bin FILE]"
            )
        );
    }

    /// ´test:unit:usage-names-repair-and-triage-cap´
    #[test]
    fn usage_names_repair_and_triage_cap() {
        assert!(USAGE.contains("repair LOOP [--dry-run]"));
        assert!(
            USAGE.contains("triage LOOP [RUN (compatibility array)] (stdin cap 65,536 bytes; about 100 typical 600-byte label lines)")
        );
    }

    /// ´test:unit:private-checkout-binds-an-external-destination-parent´
    #[test]
    fn private_checkout_binds_an_external_destination_parent() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let owner = nix::unistd::Uid::effective().as_raw();
        let ancestor = fixture.path().join("namespace-overflow-ancestor");
        fs::create_dir(&ancestor).expect("ancestor");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o770))
            .expect("untrusted ancestor mode");
        let home = ancestor.join("owner");
        let runs = home.join("runs");
        let outside = ancestor.join("outside");
        for path in [&home, &runs, &outside] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let home_fd = fs::File::open(&home).expect("home descriptor");
        let runs_fd = fs::File::open(&runs).expect("runs descriptor");
        let outside_fd = fs::File::open(&outside).expect("outside descriptor");
        let body = super::launch::checkout::private_checkout_argv(
            &super::launch::checkout::CheckoutRequest {
                loop_name: "alpha".into(),
                run: "R".into(),
                repo: "tools".into(),
                into: outside.join("R"),
                dry_run: true,
                invocation_token: None,
            },
            &home,
            None,
        )
        .expect("public checkout builder");
        let mut argv = body.clone();
        argv.extend([
            "--verified-home-fd".into(),
            "0".into(),
            "--verified-runs-root".into(),
            runs.display().to_string(),
            "--verified-runs-root-fd".into(),
            runs_fd.as_raw_fd().to_string(),
            "--verified-letter-dir".into(),
            outside.display().to_string(),
            "--verified-letter-fd".into(),
            outside_fd.as_raw_fd().to_string(),
        ]);
        let (parsed, guard) =
            bind_private_launch_args(&argv, &home_fd, owner).expect("bound checkout");
        assert_eq!(parsed, body);
        assert!(guard.is_some());
    }

    /// ´test:unit:refusal-line-reports-wall-seconds´
    #[test]
    fn refusal_line_reports_wall_seconds() {
        let error = LaneError::input("settings-grant", "missing Codex backend");
        assert_eq!(
            refusal_line(&error, 0.125),
            "settings-grant: missing Codex backend wall_seconds=0.125000"
        );
    }

    /// ´test:unit:private-launch-requires-matching-inherited-home´
    #[test]
    fn private_launch_requires_matching_inherited_home() {
        let fixture = tempfile::TempDir::new().expect("fixture");
        let owner = nix::unistd::Uid::effective().as_raw();
        let home = fixture.path().join("home");
        let other = fixture.path().join("other");
        for path in [&home, &other] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let home_fd = fs::File::open(&home).expect("home descriptor");
        let other_fd = fs::File::open(&other).expect("other descriptor");
        let runs = home.join("runs");
        fs::create_dir(&runs).expect("runs root");
        fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let runs_fd = fs::File::open(&runs).expect("runs descriptor");
        let body = [
            "_choose-uid",
            "alpha",
            "R",
            "--owner-home",
            home.to_str().expect("home path"),
        ]
        .map(String::from);
        assert_eq!(
            bind_private_launch_args(&body, &home_fd, owner)
                .err()
                .expect("missing descriptor argument")
                .kind,
            "verified-prefix"
        );
        let mut argv = body.to_vec();
        argv.extend([
            "--verified-home-fd".into(),
            "0".into(),
            "--verified-runs-root".into(),
            runs.display().to_string(),
            "--verified-runs-root-fd".into(),
            runs_fd.as_raw_fd().to_string(),
        ]);
        assert_eq!(
            bind_private_launch_args(&argv, &other_fd, owner)
                .err()
                .expect("mismatched descriptor")
                .kind,
            "verified-prefix"
        );
        let mut wrong_runs = argv.clone();
        *wrong_runs.last_mut().expect("runs descriptor") = other_fd.as_raw_fd().to_string();
        assert_eq!(
            bind_private_launch_args(&wrong_runs, &home_fd, owner)
                .err()
                .expect("mismatched runs descriptor")
                .kind,
            "socket-dir-handoff"
        );
        *wrong_runs.last_mut().expect("runs descriptor") = "999999".into();
        assert_eq!(
            bind_private_launch_args(&wrong_runs, &home_fd, owner)
                .err()
                .expect("unopened runs descriptor")
                .kind,
            "socket-dir-handoff"
        );
        let (parsed, guard) =
            bind_private_launch_args(&argv, &home_fd, owner).expect("matching descriptor");
        assert_eq!(parsed, body);
        assert!(guard.is_some());
        fs::rename(&home, fixture.path().join("retired-home")).expect("move home pathname");
        fs::create_dir(&home).expect("replacement home pathname");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("replacement mode");
        let pinned =
            superloop_lane::home::pin_parent(&home, owner).expect("held home stays active");
        assert_eq!(
            nix::sys::stat::fstat(&home_fd).expect("held inode").st_ino,
            nix::sys::stat::fstat(&pinned)
                .expect("private inode")
                .st_ino
        );
    }

    /// ´test:unit:private-import-binds-owner-home-after-object-argument´
    #[test]
    fn private_import_binds_owner_home_after_object_argument() {
        let fixture = tempfile::TempDir::new().expect("fixture");
        let owner = nix::unistd::Uid::effective().as_raw();
        let home = fixture.path().join("home");
        let runs = fixture.path().join("runs");
        for path in [&home, &runs] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        let home_fd = fs::File::open(&home).expect("home descriptor");
        let runs_fd = fs::File::open(&runs).expect("runs descriptor");
        let body = vec![
            "_mark-imported".into(),
            "alpha".into(),
            "R".into(),
            "--object".into(),
            "a".repeat(40),
            "--owner-home".into(),
            home.display().to_string(),
        ];
        let mut argv = body.clone();
        argv.extend([
            "--verified-home-fd".into(),
            "0".into(),
            "--verified-runs-root".into(),
            runs.display().to_string(),
            "--verified-runs-root-fd".into(),
            runs_fd.as_raw_fd().to_string(),
        ]);
        let (parsed, guard) =
            bind_private_launch_args(&argv, &home_fd, owner).expect("bound import request");
        assert_eq!(parsed, body);
        assert!(guard.is_some());
    }

    /// ´test:unit:private-make-home-requires-matching-letter-directory-descriptor´
    #[test]
    fn private_make_home_requires_matching_letter_directory_descriptor() {
        let fixture = tempfile::TempDir::new().expect("fixture");
        let owner = nix::unistd::Uid::effective().as_raw();
        let home = fixture.path().join("home");
        let runs = fixture.path().join("runs");
        let letters = fixture.path().join("letters");
        let other = fixture.path().join("other");
        for path in [&home, &runs, &letters, &other] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        let home_fd = fs::File::open(&home).expect("home descriptor");
        let runs_fd = fs::File::open(&runs).expect("runs descriptor");
        let letter_fd = fs::File::open(&letters).expect("letter directory descriptor");
        let other_fd = fs::File::open(&other).expect("wrong descriptor");
        let body = vec![
            "_make-home".into(),
            "alpha".into(),
            "R".into(),
            "--letter".into(),
            letters.join("first.md").display().to_string(),
            "--owner-home".into(),
            home.display().to_string(),
            "--worker-uid".into(),
            "3000".into(),
            "--podman-bin".into(),
            "/usr/bin/podman".into(),
        ];
        let mut argv = body.clone();
        argv.extend([
            "--verified-home-fd".into(),
            "0".into(),
            "--verified-runs-root".into(),
            runs.display().to_string(),
            "--verified-runs-root-fd".into(),
            runs_fd.as_raw_fd().to_string(),
            "--verified-letter-dir".into(),
            letters.display().to_string(),
            "--verified-letter-fd".into(),
            letter_fd.as_raw_fd().to_string(),
        ]);
        assert_eq!(
            bind_private_launch_args(&argv[..argv.len() - 2], &home_fd, owner)
                .err()
                .expect("missing letter descriptor")
                .kind,
            "verified-prefix"
        );
        *argv.last_mut().expect("letter descriptor") = other_fd.as_raw_fd().to_string();
        assert_eq!(
            bind_private_launch_args(&argv, &home_fd, owner)
                .err()
                .expect("mismatched letter descriptor")
                .kind,
            "verified-prefix"
        );
        *argv.last_mut().expect("letter descriptor") = letter_fd.as_raw_fd().to_string();
        let (parsed, guard) = bind_private_launch_args(&argv, &home_fd, owner)
            .expect("matching external letter descriptor");
        assert_eq!(parsed, body);
        assert!(guard.is_some());
    }

    /// ´test:unit:private-launch-preflight-reads-settings-and-ledger-beneath-home´
    #[test]
    fn private_launch_preflight_reads_settings_and_ledger_beneath_home() {
        let fixture = tempfile::TempDir::new().expect("fixture");
        let owner = nix::unistd::Uid::effective().as_raw();
        let ancestor = fixture.path().join("namespace-overflow-ancestor");
        let home = ancestor.join("home");
        let root = home.join(".config/loops");
        let runs = home.join("runs");
        let settings_dir = root.join("alpha");
        fs::create_dir_all(&settings_dir).expect("settings tree");
        fs::create_dir(&runs).expect("runs root");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o770))
            .expect("untrusted ancestor mode");
        for path in [&home, &home.join(".config"), &root, &settings_dir, &runs] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private directory mode");
        }
        let registry = root.join("registry.toml");
        fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"src\" }]\n").expect("registry");
        let ledger = root.join("allocations.toml");
        fs::write(&ledger, "[alpha]\nuids = { base = 3000, count = 64 }\n").expect("ledger");
        let settings = settings_dir.join("workers.toml");
        fs::write(
            &settings,
            "backend_argv = { codex = [\"/usr/bin/codex\"] }\n",
        )
        .expect("settings");
        for path in [&registry, &ledger, &settings] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("private file mode");
        }
        assert!(loop_home::allocations::Allocations::read(&ledger).is_err());
        let fd = fs::File::open(&home).expect("bound home");
        let runs_fd = fs::File::open(&runs).expect("bound runs root");
        let argv = vec![
            "_prepare-runtime".into(),
            "alpha".into(),
            "R".into(),
            "--owner-home".into(),
            home.display().to_string(),
            "--podman-bin".into(),
            "/usr/bin/podman".into(),
            "--verified-home-fd".into(),
            "0".into(),
            "--verified-runs-root".into(),
            runs.display().to_string(),
            "--verified-runs-root-fd".into(),
            runs_fd.as_raw_fd().to_string(),
        ];
        let (_body, guard) =
            bind_private_launch_args(&argv, &fd, owner).expect("private entry binding");
        assert!(
            superloop_lane::settings::Settings::read(&settings)
                .expect("private settings")
                .configures("codex")
        );
        let block = superloop_lane::home::read_allocations(&home)
            .expect("private ledger")
            .require("alpha")
            .expect("allocation");
        assert_eq!((block.base, block.count), (3000, 64));
        drop(guard);
    }
}
