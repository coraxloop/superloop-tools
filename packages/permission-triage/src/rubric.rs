//! Embedded and owner-supplied permission-classification rubrics.

use std::env;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[cfg(target_os = "linux")]
use crate::role::OPEN_NO_FOLLOW;

/// Maximum accepted owner-rubric size.
pub const MAX_OWNER_RUBRIC_BYTES: u64 = 64 * 1024;

/// Reviewed general-rubric bytes embedded in every build.
pub const GENERAL_RUBRIC: &str = include_str!("../rubrics/general.md");

/// SHA-256 digest of [`GENERAL_RUBRIC`].
pub const GENERAL_RUBRIC_DIGEST: &str =
    "352c65e4e251864d8da00599388877dffcf03242e8649b13c8aa63fbc2c098a7";

use execute_command::rubric::append_untrusted;
pub use execute_command::rubric::{SYSTEM_INSTRUCTION, sha256_digest};

const OWNER_RUBRIC_VARIABLE: &str = "PERMISSION_TRIAGE_OWNER_RUBRIC";
#[cfg(target_os = "linux")]
const LOOP_ERROR: i32 = 40;
static PROMPT_CLOCK: OnceLock<Instant> = OnceLock::new();
static PROMPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
/// One optional owner rubric and the digest of its exact bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerRubric {
    text: String,
    digest: String,
}

impl OwnerRubric {
    /// Complete owner-rubric text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Lowercase hexadecimal SHA-256 digest of the loaded bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// The immutable general rubric and optional loaded owner rubric.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rubrics {
    owner: Option<OwnerRubric>,
    domain: Option<OwnerRubric>,
}

impl Rubrics {
    /// Embedded general-rubric text.
    #[must_use]
    pub const fn general(&self) -> &'static str {
        GENERAL_RUBRIC
    }

    /// Digest identifying the embedded general-rubric bytes.
    #[must_use]
    pub const fn general_digest(&self) -> &'static str {
        GENERAL_RUBRIC_DIGEST
    }

    /// Loaded owner rubric, when the configured file exists.
    #[must_use]
    pub const fn owner(&self) -> Option<&OwnerRubric> {
        self.owner.as_ref()
    }

    /// Loaded domain rubric, when the resolved loop's conventional file exists.
    #[must_use]
    pub const fn domain(&self) -> Option<&OwnerRubric> {
        self.domain.as_ref()
    }
}

/// The configured rubric one loading failure concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RubricSource {
    /// The owner rubric selected by the deployment environment.
    Owner,
    /// The domain rubric of the resolved loop.
    Domain,
}

/// Owner-rubric loading failure.
#[derive(Debug)]
pub enum RubricError {
    /// The path environment variable was not valid Unicode.
    OwnerPathEncoding,
    /// The configured path was not absolute.
    OwnerPathNotAbsolute(PathBuf),
    /// Metadata for the configured path could not be read.
    OwnerMetadata(io::Error),
    /// The final path component was a symbolic link.
    OwnerFinalSymlink,
    /// The final path component was not a regular file.
    OwnerNotRegularFile,
    /// The rubric could not be opened read-only without following a final symlink.
    OwnerOpen(io::Error),
    /// Metadata for the opened file could not be read.
    OwnerFileMetadata(io::Error),
    /// The owner rubric exceeded 64 KiB.
    OwnerTooLarge(u64),
    /// Reading the bounded owner rubric failed.
    OwnerRead(io::Error),
    /// Owner-rubric bytes were not valid UTF-8.
    OwnerInvalidUtf8,
}

impl fmt::Display for RubricError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerPathEncoding => write!(formatter, "owner rubric path is not valid Unicode"),
            Self::OwnerPathNotAbsolute(path) => write!(
                formatter,
                "owner rubric path is not absolute: {}",
                path.display()
            ),
            Self::OwnerMetadata(error) => {
                write!(formatter, "owner rubric metadata failed: {error}")
            }
            Self::OwnerFinalSymlink => {
                write!(formatter, "owner rubric final component is a symbolic link")
            }
            Self::OwnerNotRegularFile => write!(formatter, "owner rubric is not a regular file"),
            Self::OwnerOpen(error) => write!(formatter, "owner rubric open failed: {error}"),
            Self::OwnerFileMetadata(error) => {
                write!(formatter, "opened owner rubric metadata failed: {error}")
            }
            Self::OwnerTooLarge(size) => write!(
                formatter,
                "owner rubric is {size} bytes, exceeding the {MAX_OWNER_RUBRIC_BYTES}-byte cap"
            ),
            Self::OwnerRead(error) => write!(formatter, "owner rubric read failed: {error}"),
            Self::OwnerInvalidUtf8 => write!(formatter, "owner rubric is not valid UTF-8"),
        }
    }
}

impl std::error::Error for RubricError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OwnerMetadata(error)
            | Self::OwnerOpen(error)
            | Self::OwnerFileMetadata(error)
            | Self::OwnerRead(error) => Some(error),
            Self::OwnerPathEncoding
            | Self::OwnerPathNotAbsolute(_)
            | Self::OwnerFinalSymlink
            | Self::OwnerNotRegularFile
            | Self::OwnerTooLarge(_)
            | Self::OwnerInvalidUtf8 => None,
        }
    }
}

/// Load the embedded general rubric and the owner rubric selected by the environment.
///
/// An unset variable or a missing owner-rubric file returns the general rubric alone.
///
/// # Errors
///
/// Returns [`RubricError`] for an invalid configured path, unsafe file type, oversized file,
/// invalid UTF-8, or any file error other than absence.
pub fn load_rubrics() -> Result<Rubrics, RubricError> {
    load_rubrics_from_environment_value(env::var_os(OWNER_RUBRIC_VARIABLE))
}

fn load_rubrics_from_environment_value(
    value: Option<std::ffi::OsString>,
) -> Result<Rubrics, RubricError> {
    let configured = match value {
        None => None,
        Some(path) if path.is_empty() => None,
        Some(path) => Some(
            path.into_string()
                .map(PathBuf::from)
                .map_err(|_path| RubricError::OwnerPathEncoding)?,
        ),
    };
    load_rubrics_from_path(configured.as_deref())
}

/// Load an explicitly selected owner-rubric path.
///
/// This is the same secure loader used by [`load_rubrics`], with environment selection left to
/// the caller.
///
/// # Errors
///
/// Returns [`RubricError`] for a relative path, unsafe file type, oversized file, invalid UTF-8,
/// or any file error other than absence.
pub fn load_rubrics_from_path(path: Option<&Path>) -> Result<Rubrics, RubricError> {
    load_rubrics_from_paths(path, None)
}

/// Load explicitly selected owner- and domain-rubric paths through one secure implementation.
///
/// # Errors
///
/// Returns [`RubricError`] for a relative path, unsafe file type, oversized file, invalid UTF-8,
/// or any file error other than absence.
pub fn load_rubrics_from_paths(
    owner_path: Option<&Path>,
    domain_path: Option<&Path>,
) -> Result<Rubrics, RubricError> {
    let owner = owner_path.map(load_owner_rubric).transpose()?.flatten();
    let domain = domain_path.map(load_owner_rubric).transpose()?.flatten();
    Ok(Rubrics { owner, domain })
}

/// Load environment-selected owner bytes and an explicitly resolved domain-rubric path.
///
/// The failing rubric is named alongside the error so a caller can say which configured file
/// its summary concerns.
///
/// # Errors
///
/// Returns [`RubricSource`] and [`RubricError`] when either selected rubric cannot be loaded
/// safely.
pub fn load_rubrics_for_domain(
    domain_path: Option<&Path>,
) -> Result<Rubrics, (RubricSource, RubricError)> {
    let owner_path = configured_owner_path(env::var_os(OWNER_RUBRIC_VARIABLE))
        .map_err(|error| (RubricSource::Owner, error))?;
    let owner = owner_path
        .as_deref()
        .map(load_owner_rubric)
        .transpose()
        .map_err(|error| (RubricSource::Owner, error))?
        .flatten();
    let domain = domain_path
        .map(load_owner_rubric)
        .transpose()
        .map_err(|error| (RubricSource::Domain, error))?
        .flatten();
    Ok(Rubrics { owner, domain })
}

/// Roots named by valid backtick-quoted rubric spans, in their original order.
#[must_use]
pub(crate) fn rubric_roots(text: &str) -> Vec<String> {
    rubric_root_spans(text).map(str::to_owned).collect()
}

pub(crate) fn rubric_root_spans(text: &str) -> impl Iterator<Item = &str> {
    text.split('`')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, root)| root)
        .filter(|root| {
            *root != "/"
                && root.starts_with('/')
                && root.ends_with('/')
                && !root.contains("/../")
                && !root.contains("/./")
                && root
                    .split('/')
                    .all(|component| component.bytes().filter(|byte| *byte == b'*').count() <= 1)
        })
}

pub(crate) fn rubric_root_matches(root: &str, path: &Path, literal_wildcards: bool) -> bool {
    let mut target = path.components();
    Path::new(root).components().all(|component| {
        let Some(candidate) = target.next() else {
            return false;
        };
        if component == candidate {
            return true;
        }
        let Some(pattern) = component.as_os_str().to_str() else {
            return false;
        };
        let Some(name) = candidate.as_os_str().to_str() else {
            return false;
        };
        if literal_wildcards && name.contains('*') {
            return false;
        }
        pattern.split_once('*').is_some_and(|(prefix, suffix)| {
            !suffix.contains('*')
                && name.starts_with(prefix)
                && name.ends_with(suffix)
                && name.len() >= prefix.len() + suffix.len()
        })
    })
}

/// Worker roots not covered by an orchestrator rubric, in worker rubric order.
#[must_use]
pub fn refused_worker_rubric_roots(orchestrator: &str, worker: &str) -> Vec<String> {
    let bounds = rubric_roots(orchestrator);
    rubric_roots(worker)
        .into_iter()
        .filter(|root| {
            !bounds
                .iter()
                .any(|bound| rubric_root_matches(bound, Path::new(root), true))
        })
        .collect()
}

fn configured_owner_path(
    value: Option<std::ffi::OsString>,
) -> Result<Option<PathBuf>, RubricError> {
    match value {
        None => Ok(None),
        Some(path) if path.is_empty() => Ok(None),
        Some(path) => path
            .into_string()
            .map(PathBuf::from)
            .map(Some)
            .map_err(|_path| RubricError::OwnerPathEncoding),
    }
}

fn load_owner_rubric(path: &Path) -> Result<Option<OwnerRubric>, RubricError> {
    if !path.is_absolute() {
        return Err(RubricError::OwnerPathNotAbsolute(path.to_path_buf()));
    }
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(RubricError::OwnerMetadata(error)),
    };
    if metadata.file_type().is_symlink() {
        return Err(RubricError::OwnerFinalSymlink);
    }
    if !metadata.is_file() {
        return Err(RubricError::OwnerNotRegularFile);
    }
    if metadata.len() > MAX_OWNER_RUBRIC_BYTES {
        return Err(RubricError::OwnerTooLarge(metadata.len()));
    }

    let file = open_owner_rubric(path)?;
    let opened_metadata = file.metadata().map_err(RubricError::OwnerFileMetadata)?;
    if !opened_metadata.is_file() {
        return Err(RubricError::OwnerNotRegularFile);
    }
    if opened_metadata.len() > MAX_OWNER_RUBRIC_BYTES {
        return Err(RubricError::OwnerTooLarge(opened_metadata.len()));
    }
    read_owner_rubric(file)
}

fn open_owner_rubric(path: &Path) -> Result<File, RubricError> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_NO_FOLLOW)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(RubricError::OwnerOpen(error)),
        Err(error) if error.raw_os_error() == Some(LOOP_ERROR) => {
            Err(RubricError::OwnerFinalSymlink)
        }
        Err(error) => Err(RubricError::OwnerOpen(error)),
    }
}

fn read_owner_rubric(file: File) -> Result<Option<OwnerRubric>, RubricError> {
    let mut bytes = Vec::new();
    file.take(MAX_OWNER_RUBRIC_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(RubricError::OwnerRead)?;
    if bytes.len() as u64 > MAX_OWNER_RUBRIC_BYTES {
        return Err(RubricError::OwnerTooLarge(bytes.len() as u64));
    }
    let digest = sha256_digest(&bytes);
    let text = String::from_utf8(bytes).map_err(|_error| RubricError::OwnerInvalidUtf8)?;
    Ok(Some(OwnerRubric { text, digest }))
}

/// Complete length-delimited input for one nested classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt(String);

impl Prompt {
    /// Build the classifier input from the only context the model may receive.
    #[must_use]
    pub fn build(rubrics: &Rubrics, tool_name: &str, cwd: &str, action: &str) -> Self {
        Self::build_for_role(rubrics, "role=unknown", tool_name, cwd, action)
    }

    /// Build classifier input with one hook-derived closed caller-role line.
    #[must_use]
    pub fn build_for_role(
        rubrics: &Rubrics,
        role: &str,
        tool_name: &str,
        cwd: &str,
        action: &str,
    ) -> Self {
        let owner = rubrics.owner().map_or("", OwnerRubric::text);
        let domain = rubrics.domain().map_or("", OwnerRubric::text);
        let nonce = prompt_nonce(&[
            SYSTEM_INSTRUCTION,
            GENERAL_RUBRIC,
            owner,
            role,
            domain,
            tool_name,
            cwd,
            action,
        ]);
        let mut prompt = String::with_capacity(
            SYSTEM_INSTRUCTION.len()
                + GENERAL_RUBRIC.len()
                + owner.len()
                + role.len()
                + domain.len()
                + tool_name.len()
                + cwd.len()
                + action.len()
                + 512,
        );
        prompt.push_str("=== REPLACEMENT SYSTEM INSTRUCTION ===\n");
        prompt.push_str(SYSTEM_INSTRUCTION);
        prompt.push('\n');
        append_untrusted(&mut prompt, "GENERAL RUBRIC", &nonce, GENERAL_RUBRIC);
        append_untrusted(&mut prompt, "OWNER RUBRIC", &nonce, owner);
        append_untrusted(&mut prompt, "CALLER ROLE", &nonce, role);
        append_untrusted(&mut prompt, "DOMAIN RUBRIC", &nonce, domain);
        append_untrusted(&mut prompt, "TOOL NAME", &nonce, tool_name);
        append_untrusted(&mut prompt, "CURRENT WORKING DIRECTORY", &nonce, cwd);
        append_untrusted(
            &mut prompt,
            "CANONICAL COMMAND OR REDUCED ACTION",
            &nonce,
            action,
        );
        Self(prompt)
    }

    /// Borrow the complete prompt text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn prompt_nonce(values: &[&str]) -> String {
    let clock = PROMPT_CLOCK.get_or_init(Instant::now);
    let sequence = PROMPT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut seed = Vec::new();
    seed.extend_from_slice(&std::process::id().to_be_bytes());
    seed.extend_from_slice(&clock.elapsed().as_nanos().to_be_bytes());
    seed.extend_from_slice(&sequence.to_be_bytes());
    for value in values {
        seed.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        seed.extend_from_slice(value.as_bytes());
    }
    sha256_digest(&seed)
}

#[cfg(test)]
pub(crate) fn load_rubrics_from_test_environment_value(
    value: Option<std::ffi::OsString>,
) -> Result<Rubrics, RubricError> {
    load_rubrics_from_environment_value(value)
}
