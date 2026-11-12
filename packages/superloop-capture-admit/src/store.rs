use crate::{
    Result,
    cli::{Config, Operation, valid_name},
    copy,
    manifest::{self, Manifest},
};
use nix::fcntl::{Flock, FlockArg};
use nix::unistd::geteuid;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct Layout {
    root: PathBuf,
    created: Vec<PathBuf>,
    temporary: Vec<PathBuf>,
    committed: bool,
}
impl Drop for Layout {
    fn drop(&mut self) {
        for path in self.temporary.iter().rev() {
            if path.is_dir() {
                let _ignored = fs::remove_dir_all(path);
            } else {
                let _ignored = fs::remove_file(path);
            }
        }
        if !self.committed {
            for path in self.created.iter().rev() {
                let _ignored = fs::remove_dir(path);
            }
        }
    }
}
pub fn run(config: Config) -> Result<Vec<u8>> {
    if geteuid().is_root() {
        return Err("root-uid-refused".into());
    }
    let root = copy::directory(&config.store)?;
    let meta = root.metadata()?;
    if meta.uid() != geteuid().as_raw() || meta.mode() & 0o7777 != 0o750 {
        return Err("store-owner-or-mode: require effective uid and 0750".into());
    }
    let locked = Flock::lock(root, FlockArg::LockExclusiveNonblock)
        .map_err(|(_, e)| format!("store-busy: {e}"))?;
    let mut layout = layout(copy::pinned(&locked))?;
    let report = match config.operation {
        Operation::Prune => prune(&layout)?,
        Operation::Admit {
            source,
            manifest,
            name,
            keep,
            quota,
        } => {
            let manifest = manifest::parse(&read_regular(&manifest)?)?;
            admit(&mut layout, &source, &manifest, &name, keep, quota)?
        }
    };
    for name in ["generations", "receipts", "leases", ".incoming"] {
        copy::directory(&layout.root.join(name))?.sync_all()?;
    }
    locked.sync_all()?;
    layout.committed = true;
    Ok(report)
}
fn layout(root: PathBuf) -> Result<Layout> {
    let group = fs::metadata(&root)?.gid();
    let mut result = Layout {
        root,
        created: Vec::new(),
        temporary: Vec::new(),
        committed: false,
    };
    for (name, mode) in [
        ("generations", 0o755),
        ("receipts", 0o755),
        ("leases", 0o770),
        (".incoming", 0o700),
    ] {
        let path = result.root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.is_dir()
                    || meta.uid() != geteuid().as_raw()
                    || meta.mode() & 0o7777 != mode
                    || meta.gid() != group
                {
                    return Err(format!("store-layout-mode: {name}").into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(mode).create(&path)?;
                result.created.push(path.clone());
                nix::unistd::chown(&path, None, Some(nix::unistd::Gid::from_raw(group)))?;
                fs::set_permissions(&path, Permissions::from_mode(mode))?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(result)
}
fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("not-regular-file".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn current(root: &Path) -> Result<Option<String>> {
    match fs::read_link(root.join("current")) {
        Ok(path) => {
            let value = path
                .to_str()
                .and_then(|p| p.strip_prefix("generations/"))
                .filter(|n| valid_name(n))
                .ok_or("invalid-current")?;
            if !fs::symlink_metadata(root.join(&path))?.is_dir() {
                return Err("invalid-current-target".into());
            }
            Ok(Some(value.to_owned()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn receipt(root: &Path, name: &str) -> Result<(String, u64)> {
    let bytes = read_regular(&root.join("receipts").join(format!("{name}.receipt")))?;
    let lines: Vec<_> = bytes
        .split_inclusive(|b| *b == b'\n')
        .map(|line| line.strip_suffix(b"\n").unwrap_or(line))
        .collect();
    let tail = lines
        .get(lines.len().checked_sub(4).ok_or("invalid-receipt")?..)
        .ok_or("invalid-receipt")?;
    if tail[0] != format!("name={name}").as_bytes() {
        return Err("invalid-receipt-name".into());
    }
    let digest = std::str::from_utf8(tail[1])?
        .strip_prefix("digest=")
        .ok_or("invalid-receipt-digest")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid-receipt-digest".into());
    }
    let _files: u64 = std::str::from_utf8(tail[2])?
        .strip_prefix("files=")
        .ok_or("invalid-receipt-files")?
        .parse()?;
    let size = std::str::from_utf8(tail[3])?
        .strip_prefix("bytes=")
        .ok_or("invalid-receipt-bytes")?
        .parse()?;
    Ok((digest.to_owned(), size))
}
fn generations(root: &Path) -> Result<Vec<(String, u64)>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root.join("generations"))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid-generation-name")?;
        if !valid_name(&name) || !entry.file_type()?.is_dir() {
            return Err("invalid-generation".into());
        }
        match fs::symlink_metadata(root.join("receipts").join(format!("{name}.receipt"))) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        result.push((name.clone(), receipt(root, &name)?.1));
    }
    result.sort();
    Ok(result)
}
fn admit(
    layout: &mut Layout,
    source: &Path,
    manifest: &Manifest,
    name: &str,
    keep: bool,
    quota: u64,
) -> Result<Vec<u8>> {
    let root = layout.root.clone();
    let previous = current(&root)?;
    let existing = generations(&root)?;
    if existing.iter().any(|(n, _)| n == name) {
        if receipt(&root, name)?.0 != manifest.digest {
            return Err(
                "identity-conflict: name already sealed with another manifest digest".into(),
            );
        }
        return Ok(format!(
            "already-sealed\nname={name}\ndigest={}\nfiles={}\nbytes={}\n",
            manifest.digest,
            manifest.entries.len(),
            manifest.bytes
        )
        .into_bytes());
    }
    let used = existing.iter().try_fold(0_u64, |sum, (_, size)| {
        sum.checked_add(*size).ok_or("store-size-overflow")
    })?;
    if used
        .checked_add(manifest.bytes)
        .is_none_or(|size| size > quota)
    {
        let (protected, _) = protection(&root)?;
        let reclaim: Vec<_> = existing
            .iter()
            .filter(|(n, _)| !protected.contains(n))
            .map(|(n, _)| n.as_str())
            .collect();
        let reclaimable: u64 = existing
            .iter()
            .filter(|(n, _)| !protected.contains(n))
            .map(|(_, size)| size)
            .sum();
        let sufficient = manifest.bytes <= quota && used - reclaimable <= quota - manifest.bytes;
        return Err(format!(
            "quota-exceeded: used={used} candidate={} quota={quota}; prune candidates={} reclaimable={reclaimable} sufficient={sufficient}",
            manifest.bytes,
            reclaim.join(",")
        )
        .into());
    }
    let mut keep_bytes = optional_keep(&root)?;
    if keep && let Some(old) = previous {
        writeln!(keep_bytes, "{old}")?;
    }
    let target = root.join("generations").join(name);
    if target.try_exists()? {
        return Err("unsealed-generation-name: receipt missing; name remains reserved".into());
    }
    let receipt_path = root.join("receipts").join(format!("{name}.receipt"));
    if receipt_path.try_exists()? {
        return Err("orphan-receipt".into());
    }
    let incoming = root
        .join(".incoming")
        .join(format!("{name}.{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&incoming)?;
    layout.temporary.push(incoming.clone());
    copy::verified(source, &incoming, manifest)?;
    let fields = format!(
        "name={name}\ndigest={}\nfiles={}\nbytes={}\n",
        manifest.digest,
        manifest.entries.len(),
        manifest.bytes
    );
    let mut contents = manifest.headers.clone();
    contents.extend_from_slice(fields.as_bytes());
    let staged_receipt = stage(layout, "receipt", &contents)?;
    let staged_keep = if keep {
        Some(stage(layout, "keep", &keep_bytes)?)
    } else {
        None
    };
    let link = root.join(format!("current.tmp.{}", std::process::id()));
    symlink(Path::new("generations").join(name), &link)?;
    layout.temporary.push(link.clone());
    fs::rename(&incoming, &target)?;
    // Roll back publication if the receipt or selector cannot be installed.
    if let Err(error) = publish(
        &root,
        &target,
        &staged_receipt,
        &receipt_path,
        staged_keep.as_deref(),
        &link,
    ) {
        let _ignored = fs::remove_file(&receipt_path);
        let _ignored = fs::remove_dir_all(&target);
        return Err(error);
    }
    Ok(fields.into_bytes())
}
fn publish(
    root: &Path,
    target: &Path,
    staged: &Path,
    receipt_path: &Path,
    keep: Option<&Path>,
    link: &Path,
) -> Result<()> {
    copy::directory(target.parent().ok_or("missing-parent")?)?.sync_all()?;
    fs::rename(staged, receipt_path)?;
    copy::directory(&root.join("receipts"))?.sync_all()?;
    if let Some(path) = keep {
        fs::rename(path, root.join("keep"))?;
        File::open(root)?.sync_all()?;
    }
    fs::rename(link, root.join("current"))?;
    Ok(())
}
fn stage(layout: &mut Layout, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    let path = layout
        .root
        .join(".incoming")
        .join(format!("{name}:{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    layout.temporary.push(path.clone());
    file.write_all(bytes)?;
    file.set_permissions(Permissions::from_mode(0o644))?;
    file.sync_all()?;
    Ok(path)
}
fn optional_keep(root: &Path) -> Result<Vec<u8>> {
    let path = root.join("keep");
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    let bytes = read_regular(&path)?;
    for line in bytes
        .split_inclusive(|b| *b == b'\n')
        .map(|line| line.strip_suffix(b"\n").unwrap_or(line))
    {
        if !valid_name(std::str::from_utf8(line)?) {
            return Err("invalid-keep".into());
        }
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err("invalid-keep-newline".into());
    }
    Ok(bytes)
}
fn protection(root: &Path) -> Result<(BTreeSet<String>, Vec<PathBuf>)> {
    let mut protected = BTreeSet::new();
    if let Some(name) = current(root)? {
        protected.insert(name);
    }
    for line in optional_keep(root)?
        .split_inclusive(|b| *b == b'\n')
        .map(|line| line.strip_suffix(b"\n").unwrap_or(line))
    {
        protected.insert(std::str::from_utf8(line)?.to_owned());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let mut expired = Vec::new();
    for entry in fs::read_dir(root.join("leases"))? {
        let entry = entry?;
        if entry.path().extension().is_none_or(|e| e != "lease") {
            continue;
        }
        let bytes = read_regular(&entry.path())?;
        let text = std::str::from_utf8(&bytes)?;
        let lines: Vec<_> = text.lines().collect();
        if lines.len() != 3 {
            return Err("malformed-lease: require identity, holder, expiry".into());
        }
        let name = lines[0]
            .strip_prefix("identity=")
            .filter(|n| valid_name(n))
            .ok_or("malformed-lease-identity")?;
        let _holder = lines[1]
            .strip_prefix("holder=")
            .filter(|s| !s.is_empty())
            .ok_or("malformed-lease-holder")?;
        let expiry = lines[2]
            .strip_prefix("expiry=")
            .ok_or("malformed-lease-expiry")?;
        let seconds = lane_lifecycle::parse_utc_instant(expiry).ok_or("malformed-lease-expiry")?;
        // Keep the fractional second when comparing the existing owner's decoded instant.
        let fraction: String = expiry[19..]
            .strip_prefix('.')
            .unwrap_or("")
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let now_fraction = format!("{:09}", now.subsec_nanos());
        let width = fraction.len().max(now_fraction.len());
        let passed = now.as_secs() > seconds
            || (now.as_secs() == seconds
                && format!("{now_fraction:0<width$}") >= format!("{fraction:0<width$}"));
        if passed {
            expired.push(entry.path());
        } else {
            protected.insert(name.to_owned());
        }
    }
    Ok((protected, expired))
}
fn prune(layout: &Layout) -> Result<Vec<u8>> {
    let (protected, expired) = protection(&layout.root)?;
    let candidates = generations(&layout.root)?;
    let mut report = String::new();
    let mut removed = 0_u64;
    let mut bytes = 0_u64;
    for (name, size) in candidates {
        if protected.contains(&name) {
            continue;
        }
        fs::remove_dir_all(layout.root.join("generations").join(&name))?;
        fs::remove_file(layout.root.join("receipts").join(format!("{name}.receipt")))?;
        writeln!(report, "removed={name} bytes={size}")?;
        removed += 1;
        bytes += size;
    }
    for path in expired {
        fs::remove_file(path)?;
    }
    for name in ["generations", "receipts", "leases"] {
        copy::directory(&layout.root.join(name))?.sync_all()?;
    }
    writeln!(report, "removed={removed}\nbytes={bytes}")?;
    Ok(report.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failed keep rename preserves the old selector at the publication boundary.
    ///
    /// # Panics
    /// Panics when a fixture operation or publication assertion fails.
    /// ´test:unit:keep-publication-failure-preserves-current´
    #[test]
    fn keep_publication_failure_preserves_current() {
        let temporary = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
        let root = temporary.path();
        fs::create_dir(root.join("generations")).unwrap();
        fs::create_dir(root.join("receipts")).unwrap();
        fs::create_dir(root.join("keep")).unwrap();
        fs::write(root.join("keep/blocker"), b"fixture").unwrap();
        fs::write(root.join("receipt-stage"), b"fixture receipt").unwrap();
        fs::write(root.join("keep-stage"), b"previous\n").unwrap();
        symlink("generations/previous", root.join("current")).unwrap();
        symlink("generations/next", root.join("current-stage")).unwrap();
        assert!(
            publish(
                root,
                &root.join("generations/next"),
                &root.join("receipt-stage"),
                &root.join("receipts/next.receipt"),
                Some(&root.join("keep-stage")),
                &root.join("current-stage")
            )
            .is_err()
        );
        assert_eq!(
            fs::read_link(root.join("current")).unwrap(),
            Path::new("generations/previous")
        );
        assert_eq!(fs::read(root.join("keep/blocker")).unwrap(), b"fixture");
    }
}
