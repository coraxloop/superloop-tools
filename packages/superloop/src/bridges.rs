use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

pub fn dispatch(args: &[OsString]) -> Option<u8> {
    if args.first().is_none_or(|arg| arg != "_install-bridges") {
        return None;
    }
    let result = install(&args[1..]);
    Some(match result {
        Ok(report) => u8::from(writeln!(std::io::stdout().lock(), "{report}").is_err()),
        Err(error) => {
            let _written = writeln!(std::io::stderr().lock(), "superloop bridges: {error}");
            2
        }
    })
}

fn same(source: &Path, destination: &Path) -> std::io::Result<bool> {
    let mut input = fs::File::open(source)?;
    let mut output = fs::File::open(destination)?;
    let mut left = [0_u8; 8192];
    let mut right = [0_u8; 8192];
    loop {
        let a = input.read(&mut left)?;
        let b = output.read(&mut right)?;
        if a != b {
            return Ok(false);
        }
        if left[..a] != right[..a] {
            return Ok(false);
        }
        if a == 0 {
            return Ok(true);
        }
    }
}

fn install(args: &[OsString]) -> Result<serde_json::Value, String> {
    let [registry, destination] = args else {
        return Err("expected REGISTRY PRIVATE-DIRECTORY".into());
    };
    let destination = Path::new(destination);
    if !destination.is_absolute() {
        return Err("private directory must be absolute".into());
    }
    let destination = std::env::var_os("DESTDIR")
        .filter(|s| !s.is_empty())
        .map_or_else(
            || destination.to_owned(),
            |stage| PathBuf::from(stage).join(destination.strip_prefix("/").unwrap_or(destination)),
        );
    let owner = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is required")?;
    let registry =
        loop_home::load_registry(Path::new(registry)).map_err(|e| e.message().to_owned())?;
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    let names = registry
        .rows(&owner)
        .into_iter()
        .map(|row| row.name)
        .collect::<Vec<_>>();
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(&destination)
        .map_err(|e| e.to_string())?;
    if fs::symlink_metadata(&destination)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("private directory must not be a symlink".into());
    }
    let mut changed = 0;
    let mut bridges = Vec::new();
    for name in names {
        for kind in ["gpg", "ssh"] {
            let target = destination.join(format!("{name}-{kind}"));
            bridges.push(target.clone());
            match fs::symlink_metadata(&target) {
                Ok(metadata) if !metadata.is_file() => {
                    return Err(format!(
                        "bridge destination is not a regular file: {}",
                        target.display()
                    ));
                }
                Ok(metadata)
                    if metadata.permissions().mode() & 0o777 == 0o755
                        && same(&source, &target).map_err(|e| e.to_string())? =>
                {
                    continue;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
            let next = destination.join(format!(".{name}-{kind}.{}", std::process::id()));
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&next)
                .map_err(|error| error.to_string())?;
            let copied = (|| {
                let mut input = fs::File::open(&source)?;
                std::io::copy(&mut input, &mut output)?;
                output.set_permissions(fs::Permissions::from_mode(0o755))?;
                output.sync_all()?;
                fs::rename(&next, &target)?;
                fs::File::open(&destination)?.sync_all()
            })();
            let _removed = fs::remove_file(&next);
            copied.map_err(|e| e.to_string())?;
            changed += 1;
        }
    }
    Ok(serde_json::json!({"schema":1,"changed":changed,"bridges":bridges}))
}
