//! Exclusive case objects and no-replace state receipts, all relative to held directories.
use super::{
    Result,
    measure::{self, Admission, ConfigurationMeasurement, ObjectIdentity},
    policy::Role,
    require,
    state::{Phase, State},
};
use crate::receipt;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde::Serialize;
use std::fs::{File, Permissions};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

struct Directory {
    parent: File,
    file: File,
    name: String,
    object: ObjectIdentity,
}
impl Directory {
    fn create(root: &Path, name: &str) -> Result<Self> {
        let parent = receipt::sealed_directory(root)?;
        mkdirat(&parent, name, Mode::from_bits_truncate(0o700))
            .map_err(|_| "launch-exclusive-directory")?;
        let file = File::from(
            openat(
                &parent,
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "launch-directory-open")?,
        );
        file.set_permissions(Permissions::from_mode(0o700))
            .map_err(|_| "launch-directory-mode")?;
        let object = ObjectIdentity::of(&file)?;
        parent.sync_all().map_err(|_| "launch-directory-sync")?;
        Ok(Self {
            parent,
            file,
            name: name.to_owned(),
            object,
        })
    }
    fn verify(&self) -> Result<()> {
        let current = File::from(
            openat(
                &self.parent,
                self.name.as_str(),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "launch-directory-binding")?,
        );
        let m = current.metadata().map_err(|_| "file-metadata")?;
        require(
            ObjectIdentity::of(&current)? == self.object
                && m.mode() & 0o7777 == 0o700
                && m.uid() == nix::unistd::geteuid().as_raw()
                && m.nlink() > 0,
            "launch-directory-binding",
        )
    }
}
#[derive(Serialize)]
struct Entry {
    name: String,
    object: ObjectIdentity,
}
struct Output {
    file: File,
    entry: Entry,
}
#[derive(Clone, Debug, Serialize)]
pub(super) struct Invocation {
    pub id: String,
    pub unit: String,
    pub pid: u32,
    pub birth: u64,
    pub uid: u32,
    pub image: ObjectIdentity,
}
#[derive(Serialize)]
struct Snapshot<'a> {
    schema: u32,
    command: &'static str,
    case: &'a str,
    unit: &'a str,
    sequence: u32,
    phase: Phase,
    refusal_class: Option<&'static str>,
    policy_sha256: &'a str,
    code_sha256: &'a str,
    case_sha256: &'a str,
    sealed_directory: ObjectIdentity,
    evidence_directory: ObjectIdentity,
    created_outputs: Vec<&'a Entry>,
    invocation: Option<&'a Invocation>,
    configuration: Option<&'a ConfigurationMeasurement>,
}
pub(super) struct Store {
    sealed: Directory,
    evidence: Directory,
    outputs: Vec<Output>,
    case: String,
    unit: String,
    policy_sha256: String,
    code_sha256: String,
    case_sha256: String,
    state: State,
    expected_image: ObjectIdentity,
    sealed_limit: u64,
    refusal_class: Option<&'static str>,
    invocation: Option<Invocation>,
    configuration: Option<ConfigurationMeasurement>,
}
impl Store {
    pub fn reserve(admission: &Admission, index: usize) -> Result<Self> {
        let case = admission
            .policy()
            .cases
            .get(index)
            .ok_or("launch-case-binding")?;
        let measurement = admission.cases().get(index).ok_or("launch-case-binding")?;
        let sealed = Directory::create(&admission.policy().roots.sealed, &case.id)?;
        // A failure after exclusive creation leaves private incomplete custody;
        // never infer success or delete an unrecorded object by pathname.
        let evidence = Directory::create(&admission.policy().roots.evidence, &case.id)?;
        let mut store = Self {
            sealed,
            evidence,
            outputs: Vec::new(),
            case: case.id.clone(),
            unit: case.generator_unit.clone(),
            policy_sha256: admission.policy_sha256().to_owned(),
            code_sha256: admission.code_sha256().to_owned(),
            case_sha256: measurement.sha256.clone(),
            state: State::default(),
            expected_image: admission.fixture_image(),
            invocation: None,
            configuration: None,
            sealed_limit: admission.policy().limits.sealed_bytes,
            refusal_class: None,
        };
        for stream in &case.streams {
            store
                .outputs
                .push(Output::create(&store.sealed.file, &stream.output)?);
        }
        store
            .sealed
            .file
            .sync_all()
            .map_err(|_| "launch-directory-sync")?;
        store.write_snapshot(0, Phase::Reserved)?;
        Ok(store)
    }
    pub const fn phase(&self) -> Phase {
        self.state.phase()
    }
    fn verify_outputs(&self, mode: Option<u32>) -> Result<()> {
        self.sealed.verify()?;
        self.evidence.verify()?;
        for output in &self.outputs {
            let current = File::from(
                openat(
                    &self.sealed.file,
                    output.entry.name.as_str(),
                    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                    Mode::empty(),
                )
                .map_err(|_| "launch-output-binding")?,
            );
            let m = current.metadata().map_err(|_| "file-metadata")?;
            require(
                ObjectIdentity::of(&current)? == output.entry.object
                    && m.is_file()
                    && m.nlink() == 1
                    && m.uid() == nix::unistd::geteuid().as_raw()
                    && mode.map_or_else(
                        || matches!(m.mode() & 0o7777, 0o400 | 0o600),
                        |expected| m.mode() & 0o7777 == expected,
                    ),
                "launch-output-binding",
            )?;
        }
        Ok(())
    }
    fn write_snapshot(&self, sequence: u32, phase: Phase) -> Result<()> {
        self.evidence.verify()?;
        let snapshot = Snapshot {
            schema: 1,
            command: "launch-state",
            case: &self.case,
            unit: &self.unit,
            sequence,
            phase,
            refusal_class: self.refusal_class,
            policy_sha256: &self.policy_sha256,
            code_sha256: &self.code_sha256,
            case_sha256: &self.case_sha256,
            sealed_directory: self.sealed.object,
            evidence_directory: self.evidence.object,
            created_outputs: self.outputs.iter().map(|o| &o.entry).collect(),
            invocation: self.invocation.as_ref(),
            configuration: self.configuration.as_ref(),
        };
        let bytes = serde_json::to_vec(&snapshot).map_err(|_| "launch-evidence-encoding")?;
        receipt::publish_held(
            &self.evidence.file,
            &format!("state-{sequence:02}.json"),
            &bytes,
        )
    }
    pub fn capture(&mut self, invocation: Invocation, properties: &[u8]) -> Result<()> {
        require(
            self.state.phase() == Phase::Submitted,
            "launch-capture-order",
        )?;
        require(
            invocation.unit == self.unit
                && invocation.id.len() == 32
                && invocation
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && invocation.id.bytes().any(|b| b != b'0')
                && invocation.pid > 1
                && invocation.birth > 0
                && invocation.uid > 0
                && invocation.image == self.expected_image,
            "launch-invocation-binding",
        )?;
        let configuration = measure::configuration(&Role::Fixture.properties(), properties)?;
        self.invocation = Some(invocation);
        self.configuration = Some(configuration);
        self.advance(Phase::Captured)
    }
    pub fn output_files(&self) -> Result<[&File; 2]> {
        require(
            self.state.phase() == Phase::Reserved,
            "launch-output-transfer-order",
        )?;
        Ok([&self.outputs[0].file, &self.outputs[1].file])
    }
    pub fn advance(&mut self, phase: Phase) -> Result<()> {
        require(phase != Phase::SealedSynced, "launch-sync-order")?;
        require(
            !matches!(phase, Phase::Failed | Phase::Uncertain),
            "launch-failure-class-required",
        )?;
        require(
            phase != Phase::Captured || self.invocation.is_some(),
            "launch-capture-required",
        )?;
        self.persist(phase)
    }
    // Failure classes are internal static metadata, never child diagnostic bytes.
    pub fn fail(&mut self, class: &'static str) -> Result<()> {
        self.state.next(Phase::Failed)?;
        self.check_outputs(None)?;
        self.terminal(Phase::Failed, class)
    }
    pub fn uncertain(&mut self, class: &'static str) -> Result<()> {
        self.terminal(Phase::Uncertain, class)
    }
    fn terminal(&mut self, phase: Phase, class: &'static str) -> Result<()> {
        let sequence = self.state.next(phase)?;
        self.refusal_class = Some(class);
        // Latch before publication: even publication failure cannot reopen success.
        self.state.commit(phase)?;
        if let Err(publication) = self.write_snapshot(sequence, phase) {
            self.state.publication_failed();
            self.refusal_class = Some(publication);
            let _publication = self.write_snapshot(sequence + 1, Phase::Uncertain);
            return Err(publication);
        }
        Ok(())
    }
    fn check_outputs(&mut self, mode: Option<u32>) -> Result<()> {
        if let Err(class) = self.verify_outputs(mode) {
            // Output custody is not a prerequisite for recording its loss. The
            // evidence directory must still be valid; otherwise memory stays
            // uncertain and the publication error cannot become acceptance.
            let _publication = self.uncertain(class);
            return Err(class);
        }
        Ok(())
    }
    fn persist(&mut self, phase: Phase) -> Result<()> {
        let sequence = self.state.next(phase)?;
        if matches!(self.state.phase(), Phase::SealedSynced) || phase == Phase::SealedSynced {
            self.check_outputs(Some(0o400))?;
        } else {
            self.check_outputs(Some(0o600))?;
        }
        if let Err(class) = self.write_snapshot(sequence, phase) {
            // The failed slot may already be occupied. Never replace it. Latch
            // uncertainty and attempt its separate next-sequence receipt.
            self.state.publication_failed();
            self.refusal_class = Some(class);
            let _publication = self.write_snapshot(sequence + 1, Phase::Uncertain);
            return Err(class);
        }
        self.state.commit(phase)
    }
    pub fn sync_outputs(&mut self) -> Result<()> {
        require(
            self.state.phase() == Phase::EofAndSealersComplete,
            "launch-sync-order",
        )?;
        self.check_outputs(Some(0o600))?;
        for output in &self.outputs {
            let length = output.file.metadata().map_err(|_| "file-metadata")?.len();
            require(
                (1..=self.sealed_limit).contains(&length),
                "launch-sealed-size",
            )?;
        }
        for output in &self.outputs {
            output.file.sync_all().map_err(|_| "launch-output-sync")?;
            output
                .file
                .set_permissions(Permissions::from_mode(0o400))
                .map_err(|_| "launch-output-mode")?;
            output.file.sync_all().map_err(|_| "launch-output-sync")?;
        }
        self.sealed
            .file
            .sync_all()
            .map_err(|_| "launch-directory-sync")?;
        self.persist(Phase::SealedSynced)
    }
    // Cleanup never scans a root or removes a receipt. It is terminal-only and
    // checks the entire two-output manifest before deleting any member.
    pub fn cleanup_outputs(&self) -> Result<()> {
        require(
            matches!(self.state.phase(), Phase::Failed | Phase::Uncertain),
            "launch-cleanup-state",
        )?;
        self.verify_outputs(None)?;
        for output in &self.outputs {
            unlinkat(
                &self.sealed.file,
                output.entry.name.as_str(),
                UnlinkatFlags::NoRemoveDir,
            )
            .map_err(|_| "launch-cleanup-unlink")?;
        }
        self.sealed
            .file
            .sync_all()
            .map_err(|_| "launch-directory-sync")
    }
}

impl Output {
    fn create(directory: &File, name: &str) -> Result<Self> {
        let file = File::from(
            openat(
                directory,
                name,
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|_| "launch-exclusive-output")?,
        );
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(|_| "launch-output-mode")?;
        Ok(Self {
            entry: Entry {
                name: name.to_owned(),
                object: ObjectIdentity::of(&file)?,
            },
            file,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    /// ´test:unit:launch-output-creation-is-exclusive´
    #[test]
    fn launch_output_creation_is_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
        let held = receipt::sealed_directory(dir.path()).unwrap();
        let output = Output::create(&held, "synthetic.sealed").unwrap();
        assert_eq!(output.file.metadata().unwrap().mode() & 0o7777, 0o600);
        assert_eq!(
            Output::create(&held, "synthetic.sealed").err(),
            Some("launch-exclusive-output")
        );
        assert_eq!(
            receipt::publish_held(&held, "../escape", b"{}"),
            Err("receipt-name")
        );
        assert_eq!(
            receipt::publish_held(&output.file, "state.json", b"{}"),
            Err("receipt-root-custody")
        );
    }
}
