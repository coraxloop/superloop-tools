use crate::ToggleError;
use std::env;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::project_root::project_root;

#[derive(Clone, Copy)]
pub enum ToggleCommand {
    On,
    Off,
    Status,
}

/// Read the selected project flag.
///
/// # Errors
/// Returns a redacted error when the flag cannot be inspected.
pub fn enabled(state_dir: &Path, cwd: &Path, boundary: Option<&Path>) -> Result<bool, ToggleError> {
    let root = project_root(cwd, boundary);
    let flag = state_dir.join(format!(
        "heartbeat{}",
        root.to_string_lossy().replace('/', "-")
    ));
    match fs::metadata(flag) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ToggleError),
    }
}

/// Run the selected toggle operation.
///
/// # Errors
/// Returns a redacted error when configuration, state access or formatting fails.
pub fn execute(command: ToggleCommand, state_dir: &Path) -> Result<Vec<u8>, ToggleError> {
    let cwd = env::var("PWD").map_err(|_| ToggleError)?;
    let boundary = env::var_os("HOME").map(PathBuf::from);
    let root = project_root(Path::new(&cwd), boundary.as_deref());
    if !matches!(command, ToggleCommand::Status) {
        fs::create_dir_all(state_dir).map_err(|_| ToggleError)?;
    }
    let flag = state_dir.join(format!(
        "heartbeat{}",
        root.to_string_lossy().replace('/', "-")
    ));
    let mut output = String::new();
    match command {
        ToggleCommand::On => {
            let flag_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&flag)
                .map_err(|_| ToggleError)?;
            flag_file
                .set_modified(SystemTime::now())
                .map_err(|_| ToggleError)?;
            writeln!(output, "heartbeat guard ON for {}", root.display())
                .map_err(|_| ToggleError)?;
        }
        ToggleCommand::Off => {
            if let Err(error) = fs::remove_file(&flag)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(ToggleError);
            }
            writeln!(
                output,
                "heartbeat guard OFF for {} (blocked-on-user state)",
                root.display()
            )
            .map_err(|_| ToggleError)?;
        }
        ToggleCommand::Status => {
            let status = if enabled(state_dir, Path::new(&cwd), boundary.as_deref())? {
                "ON"
            } else {
                "OFF"
            };
            writeln!(output, "{status} ({})", root.display()).map_err(|_| ToggleError)?;
        }
    }
    Ok(output.into_bytes())
}
