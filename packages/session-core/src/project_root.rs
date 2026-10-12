use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Resolve the nearest plausible repository root below an exclusive boundary.
///
/// The boundary applies when it is a lexical prefix of `cwd`, including when
/// it equals `cwd`, and is otherwise ignored so that search continues to the
/// filesystem root. The first existing `.git` entry ends the search; an
/// implausible entry or no entry leaves `cwd` unchanged.
/// A relative or empty `cwd` is returned unchanged without probing the
/// filesystem.
#[must_use]
pub fn project_root(cwd: &Path, boundary: Option<&Path>) -> PathBuf {
    if !cwd.is_absolute() {
        return cwd.to_path_buf();
    }
    let boundary = boundary.filter(|boundary| cwd.starts_with(boundary));
    cwd.ancestors()
        .take_while(|ancestor| boundary.is_none_or(|boundary| *ancestor != boundary))
        .find_map(|ancestor| match repository_marker(ancestor) {
            Marker::Missing => None,
            Marker::Plausible => Some(ancestor),
            Marker::Implausible => Some(cwd),
        })
        .map_or_else(|| cwd.to_path_buf(), Path::to_path_buf)
}

enum Marker {
    Missing,
    Plausible,
    Implausible,
}

fn repository_marker(root: &Path) -> Marker {
    let marker = root.join(".git");
    match fs::symlink_metadata(&marker) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Marker::Missing,
        Err(_) => return Marker::Implausible,
    }
    if marker.is_dir() {
        return if marker.join("HEAD").is_file() {
            Marker::Plausible
        } else {
            Marker::Implausible
        };
    }
    if !marker.is_file() {
        return Marker::Implausible;
    }
    let Ok(mut marker) = File::open(marker) else {
        return Marker::Implausible;
    };
    let mut prefix = [0_u8; 7];
    if marker.read_exact(&mut prefix).is_ok() && prefix == *b"gitdir:" {
        Marker::Plausible
    } else {
        Marker::Implausible
    }
}
