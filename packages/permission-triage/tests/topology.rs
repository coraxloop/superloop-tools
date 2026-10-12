#[path = "support/temporary_root.rs"]
mod temporary_root;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use serde_json::{Value, json};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// A fork can inherit another test thread's writable stub descriptor, making its exec fail with ETXTBSY; at commit 1303417c4, library/std/src/sys/process/unix/unix.rs waits for close-on-exec EOF or the error written after `do_exec` before returning from fork-path spawn (lines 104, 138-160).
/// That file delegates the other path to `posix_spawnp` (lines 456-475, 783); Linux glibc's `CLONE_VFORK` suspension until exec or failure is the platform premise, so the lock across stub writes and direct test-side spawns closes the inherited-descriptor window and can end before waiting for the child.
/// For output callers with unconfigured streams, library/std/src/process.rs documents inherited stdio for spawn and noninherited stdin for output (lines 1063, 1095-1096, 1103, 1138-1139), library/std/src/sys/process/mod.rs selects `MakePipe` (lines 54-57), and library/std/src/sys/process/unix/common.rs selects null stdin (lines 358-365).
static STUB_PROCESS_LOCK: Mutex<()> = Mutex::new(());

fn write_executable(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn spawn_serialized(command: &mut Command) -> std::io::Result<Child> {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    command.spawn()
}

#[allow(dead_code)]
trait SerializedCommand {
    fn spawn_serialized(&mut self) -> std::io::Result<Child>;
    fn output_serialized(&mut self) -> std::io::Result<Output>;
    fn output_serialized_with_stdin(&mut self, stdin: impl Into<Stdio>) -> std::io::Result<Output>;
    fn status_serialized(&mut self) -> std::io::Result<ExitStatus>;
}

impl SerializedCommand for Command {
    fn spawn_serialized(&mut self) -> std::io::Result<Child> {
        spawn_serialized(self)
    }

    fn output_serialized(&mut self) -> std::io::Result<Output> {
        self.output_serialized_with_stdin(Stdio::null())
    }

    fn output_serialized_with_stdin(&mut self, stdin: impl Into<Stdio>) -> std::io::Result<Output> {
        self.stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        spawn_serialized(self)?.wait_with_output()
    }

    fn status_serialized(&mut self) -> std::io::Result<ExitStatus> {
        spawn_serialized(self)?.wait()
    }
}
const FAKE_HARNESS: &[u8] = include_bytes!("topology/fake-harness.sh");

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new(name: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = temporary_root::temporary_root().join(format!(
            "permission-triage-topology-integration-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("unique topology fixture directory is created");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn probe_root(&self) -> PathBuf {
        self.0.join("probe")
    }

    fn scratch_home(&self) -> PathBuf {
        self.0.join("scratch-home")
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

fn install_fake_harness(root: &Path, executable: bool) -> PathBuf {
    fs::create_dir(root).expect("probe root is created");
    let harness = root.join("fake-harness.sh");
    let mode = if executable { 0o700 } else { 0o600 };
    write_executable(&harness, FAKE_HARNESS, mode)
        .expect("fake harness is copied beneath fixture root");
    harness
}

fn topology_command(root: &Path, home: &Path) -> Command {
    topology_command_with_binary(
        Path::new(env!("CARGO_BIN_EXE_permission-triage-topology")),
        root,
        home,
    )
}

fn topology_command_with_binary(binary: &Path, root: &Path, home: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .args([
            "--fixture-root",
            root.to_str().expect("fixture path is UTF-8"),
        ])
        .env(
            "PERMISSION_TRIAGE_HOOK_BIN",
            env!("CARGO_BIN_EXE_permission-triage-hook"),
        )
        .env_remove("PERMISSION_TRIAGE_HARNESS_ALLOW_VERSION")
        .env_remove("PERMISSION_TRIAGE_HARNESS_BIN")
        .env_remove("PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS")
        .env("HOME", home);
    command
}

const MAX_TOPOLOGY_CEILING_MS: u64 = 120_000;
const MIN_TOPOLOGY_CEILING_MS: u64 = 2_000;

/// Headroom over the measured trial, as a multiple of the sampled wall.
///
/// The sampled row is the cheapest trial the roster runs: one harness invocation with an audit hook
/// registered, where the heaviest graded trials add an enforcing hook round trip and a confirmation
/// capture on top of the same spawn. Twenty times the sampled wall covers that ratio and the
/// variance a loaded machine adds, and it opens on an idle machine too, where a two-hundred
/// millisecond trial yields four seconds rather than resting on the floor.
const TOPOLOGY_CEILING_SAMPLE_HEADROOM: u64 = 20;

/// Headroom over a wall the probe has already reported, as a multiple of that wall.
///
/// An observed wall is not the sampled row it is compared against: it is a graded trial that already
/// paid the enforcing hook round trip and the confirmation capture, taken on this machine under the
/// load the run is actually meeting. The ratio the sampled factor exists to cover is therefore
/// already inside the number, and what is left to cover is the variance between one graded trial and
/// the next — a descheduled spawn, a hook that waits longer for the same work. Four times an observed
/// wall covers that variance, so a ceiling raised from an observation stays a cap on a trial that has
/// gone wrong rather than becoming a budget any trial can spend.
const TOPOLOGY_CEILING_OBSERVED_HEADROOM: u64 = 4;

/// Largest uncensored trial wall any probe run in this binary has reported, in milliseconds.
///
/// The initial sample is taken once, while every other ceiling-needing thread is parked on the cell
/// that memoises it, so it reads the quietest moment of this binary's own run and none of the load
/// that arrives afterwards. Every completed probe run answers that with evidence the sample cannot
/// have: the walls it actually graded. They accumulate here, so a trial starting later in the run
/// stands on what the run has seen rather than on what it saw first.
static OBSERVED_TRIAL_WALL_MS: AtomicU64 = AtomicU64::new(0);

/// One fresh baseline ceiling after a verdict reports censorship.
///
/// A censored wall is a lower bound, not a completed duration. It can show that the initial sample
/// missed the load without supplying a duration to multiply. Re-sampling the baseline once measures
/// that load directly; only its uncensored walls receive the sample headroom and the existing cap.
/// The cell stores failures too, so neither repeated timeouts nor simultaneous verdict readers can
/// trigger another sample. Deliberate timeout modes may request the sample, but their timeout walls
/// cannot inflate it: the ordinary baseline harness still has to perform the measured work.
static RESAMPLED_CEILING_MS: OnceLock<Result<u64, String>> = OnceLock::new();

/// Smallest number of trial samples the ceiling may stand on.
///
/// One sample is a coin toss on a loaded machine, where a single descheduled trial reads the same
/// as a slow machine. Three samples taken in sequence let the maximum stand for the worst moment
/// the suite is about to meet.
const MIN_CEILING_SAMPLES: usize = 3;

/// Roster and mode of the sampling run: the smallest roster that still executes graded trials.
const CEILING_SAMPLE_ROSTER: &str = "baseline";
const CEILING_SAMPLE_MODE: &str = "topology-auto-executed";

fn ceiling_from_baseline_ms(baseline_ms: u64) -> u64 {
    baseline_ms
        .saturating_mul(TOPOLOGY_CEILING_SAMPLE_HEADROOM)
        .clamp(MIN_TOPOLOGY_CEILING_MS, MAX_TOPOLOGY_CEILING_MS)
}

fn ceiling_from_observed_ms(observed_max_ms: u64) -> u64 {
    observed_max_ms
        .saturating_mul(TOPOLOGY_CEILING_OBSERVED_HEADROOM)
        .clamp(MIN_TOPOLOGY_CEILING_MS, MAX_TOPOLOGY_CEILING_MS)
}

/// Ceiling a trial starting now stands on, in milliseconds.
///
/// The sampled ceiling is the floor of the run: it was measured before any of these trials ran and
/// nothing later makes it smaller. An observation raises it when the run has seen a wall the sample
/// did not anticipate, and the cap the sample obeys binds the observation too, so a single trial that
/// ran away cannot lift the ceiling past the point where a censored trial stops being reported.
fn standing_ceiling_ms(sampled_ceiling_ms: u64, observed_max_ms: u64) -> u64 {
    sampled_ceiling_ms
        .max(ceiling_from_observed_ms(observed_max_ms))
        .clamp(MIN_TOPOLOGY_CEILING_MS, MAX_TOPOLOGY_CEILING_MS)
}

/// Progress line the gates read, carrying the sample count and the sample the ceiling stands on.
fn ceiling_progress_line(samples: &[u64], ceiling_ms: u64) -> String {
    let max_sample_ms = samples.iter().copied().max().unwrap_or_default();
    format!(
        "topology-test-ceiling baseline_ms={max_sample_ms} ceiling_ms={ceiling_ms} samples={} max_sample_ms={max_sample_ms}",
        samples.len()
    )
}

/// Progress line the gates read when an observed wall raises the run's maximum.
///
/// It is printed on a rise rather than at a fixed point in the run: a test binary has no end-of-run
/// hook, and a rise is the only moment at which the number changes, so printing there reports every
/// value the ceiling ever stood on for the cost of the rises themselves.
fn observed_progress_line(observed_max_ms: u64) -> String {
    format!(
        "topology-test-ceiling-observed observed_max_ms={observed_max_ms} observed_ceiling_ms={}",
        ceiling_from_observed_ms(observed_max_ms)
    )
}

/// Wall of one sampled trial, or why the sample cannot stand on it.
///
/// A missing or null `timed_out` field is a different fault from a censored trial and names itself as
/// one: reading absence as censorship reports a probe that stopped emitting the field as a probe that
/// ran out of time, which sends the reader to the machine's load instead of to the verdict's shape.
/// A field that is present and not a boolean is a third fault and names itself as a third: a probe
/// emitting the string "true" or the number one has changed the type of what it reports, and
/// calling that an absent field sends the reader looking for a field the verdict is already
/// carrying.
fn sampled_trial_wall_ms(trial: &Value) -> Result<u64, String> {
    let timed_out = &trial["timed_out"];
    match timed_out.as_bool() {
        None if timed_out.is_null() => Err(format!(
            "the sampled trial reports no timed_out field: {}",
            trial["id"]
        )),
        None => Err(format!(
            "the sampled trial reports a timed_out field that is not a boolean: {}",
            trial["id"]
        )),
        Some(true) => Err(format!("sampled trial was censored: {}", trial["id"])),
        Some(false) => trial["invocation_wall_ms"].as_u64().ok_or_else(|| {
            format!(
                "the sampled trial reports no invocation wall: {}",
                trial["id"]
            )
        }),
    }
}

/// Largest uncensored trial wall in one verdict, in milliseconds.
///
/// A censored trial is skipped rather than measured: its wall equals the ceiling by construction, so
/// feeding it back would raise the ceiling to a multiple of itself on every run that timed one out,
/// and the cap would be reached by ratcheting rather than by evidence. Censorship instead requests
/// the separate, one-time baseline re-sample. A trial whose wall is missing is skipped because it
/// supplies no completed duration.
fn observed_trial_wall_ms(verdict: &Value) -> u64 {
    verdict["trials"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|trial| trial["timed_out"].as_bool() == Some(false))
        .filter_map(|trial| trial["invocation_wall_ms"].as_u64())
        .max()
        .unwrap_or_default()
}

fn censored_trial_count(verdict: &Value) -> usize {
    verdict["trials"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|trial| trial["timed_out"].as_bool() == Some(true))
        .count()
}

/// Request at most one baseline re-sample, remembering its success or failure across readers.
fn resample_after_censorship(
    censored_count: usize,
    resampled: &OnceLock<Result<u64, String>>,
    sample: impl FnOnce() -> Result<u64, String>,
) -> Result<(), String> {
    if censored_count == 0 {
        return Ok(());
    }
    resampled
        .get_or_init(sample)
        .as_ref()
        .map(|_| ())
        .map_err(Clone::clone)
}

/// Raise the run's observed maximum from one verdict, announcing the value when it rises.
///
/// Every site that reads a probe's verdict records it, because the walls that verdict reports are
/// evidence a later trial's ceiling can stand on and the site that read them is the only place they
/// survive. A site that reads no verdict records nothing and has nothing to withhold: a refusal
/// checked for its exit code ran no trial, and a run whose verdict write was made to fail leaves no
/// document to read. A verdict carrying no uncensored trial leaves the maximum where it stood, so
/// it cannot ratchet that maximum. Its censored trials can still request the one baseline re-sample;
/// the verdict itself stays unchanged, including any failures the original ceiling caused.
///
/// # Panics
///
/// Panics if a progress line cannot be written to standard error or the baseline re-sample fails.
fn record_observed_walls(verdict: &Value) {
    let censored_count = censored_trial_count(verdict);
    if censored_count > 0 {
        writeln!(
            std::io::stderr().lock(),
            "topology-test-ceiling-censored count={censored_count} fixture_root={}",
            verdict["fixture_root"]
        )
        .expect("the censored trial count is printed");
    }
    let observed_max_ms = observed_trial_wall_ms(verdict);
    if OBSERVED_TRIAL_WALL_MS.fetch_max(observed_max_ms, Ordering::Relaxed) < observed_max_ms {
        writeln!(
            std::io::stderr().lock(),
            "{}",
            observed_progress_line(observed_max_ms)
        )
        .expect("the observed trial wall is printed");
    }
    resample_after_censorship(censored_count, &RESAMPLED_CEILING_MS, || {
        sample_ceiling_ms(true)
    })
    .unwrap_or_else(|failure| panic!("the topology ceiling re-sample failed: {failure}"));
}

/// Verdict a probe wrote to standard output, with the walls it reports recorded as it is read.
///
/// Reading and recording are one step, so a site cannot take a verdict's assertions without leaving
/// the run the walls that verdict measured: those walls are what a later trial's ceiling stands on,
/// and a read that forgets them costs the run evidence it has already paid the probe for.
fn recorded_stdout_verdict(stdout: &[u8], expectation: &str) -> Value {
    let verdict: Value =
        serde_json::from_slice(stdout).unwrap_or_else(|error| panic!("{expectation}: {error}"));
    record_observed_walls(&verdict);
    verdict
}

/// Wall of every trial in one baseline-roster probe run, in milliseconds.
///
/// The sample has to feel machine load, so it does what a trial does: the probe spawns the harness,
/// the harness performs its hook round trip and writes a result document, and the probe reads and
/// grades it. The run is left at the probe's default ceiling so a slow sample is measured instead of
/// censored, and a censored sample is a failure rather than a number.
///
/// A failure is returned rather than raised, because the caller stores it: a panic inside the cell's
/// initialiser is not remembered, so every later test would run this probe again to reach the same
/// failure, and one sampling run costs minutes on a loaded machine. Every fault this function
/// reaches on its own takes that route — a scratch HOME that cannot be made, a probe that cannot
/// be spawned, a probe that exits non-zero, a verdict that is not JSON or carries no trials
/// array — because a fault raised here rather than returned is a fault the cell cannot store, and
/// the probe would run again for every later caller to reach the same answer. The fixture helpers
/// it calls still raise: each of their faults lands before the probe is spawned, so a caller that
/// retries pays the same directory and copy rather than the probe run this route exists to save.
fn sampled_trial_walls_ms() -> Result<Vec<u64>, String> {
    let directory = FixtureDirectory::new("ceiling-baseline");
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&home)
        .map_err(|error| format!("baseline scratch HOME is not created: {error}"))?;
    let harness = install_fake_harness(&root, true);
    let output = topology_command(&root, &home)
        .args(["--test-roster", CEILING_SAMPLE_ROSTER])
        .env("PERMISSION_TRIAGE_HARNESS_BIN", &harness)
        .env("FAKE_HARNESS_MODE", CEILING_SAMPLE_MODE)
        .output_serialized()
        .map_err(|error| format!("the baseline roster probe did not run: {error}"))?;
    if output.status.code() != Some(0) {
        return Err(format!(
            "baseline roster probe exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let verdict: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("the baseline roster verdict is not JSON: {error}"))?;
    let samples = verdict["trials"]
        .as_array()
        .ok_or_else(|| "the baseline roster verdict carries no trials array".to_owned())?
        .iter()
        .map(sampled_trial_wall_ms)
        .collect::<Result<Vec<_>, _>>()?;
    if samples.len() < MIN_CEILING_SAMPLES {
        return Err(format!("the sampling roster ran {} trials", samples.len()));
    }
    Ok(samples)
}

fn sample_ceiling_ms(resampled: bool) -> Result<u64, String> {
    let samples = sampled_trial_walls_ms()?;
    let maximum = samples
        .iter()
        .copied()
        .max()
        .ok_or("the baseline has no samples")?;
    let ceiling_ms = ceiling_from_baseline_ms(maximum);
    writeln!(
        std::io::stderr().lock(),
        "{} resampled={resampled}",
        ceiling_progress_line(&samples, ceiling_ms)
    )
    .map_err(|error| format!("the measured ceiling is not printed: {error}"))?;
    Ok(ceiling_ms)
}

fn measured_ceiling_ms() -> u64 {
    static MEASURED: OnceLock<Result<u64, String>> = OnceLock::new();
    let measured = MEASURED.get_or_init(|| sample_ceiling_ms(false));
    match measured {
        Ok(ceiling_ms) => *ceiling_ms,
        Err(failure) => panic!("the topology ceiling has no sample: {failure}"),
    }
}

/// Outcome claims use the production cap, not a quiet-node sample: parallel real hooks
/// exceeded the sampled ceiling at load 59. The 120-second cap leaves scheduling
/// headroom at the gate's load of 50–150 without adding a wait to completed trials.
/// Sampling remains diagnostic; only explicit ceiling claims use the short cap.
fn ceiling_ms(mode: &str) -> String {
    if mode == "topology-ceiling" {
        "20".to_owned()
    } else {
        standing_ceiling_ms(
            measured_ceiling_ms().max(
                RESAMPLED_CEILING_MS
                    .get()
                    .and_then(|result| result.as_ref().ok())
                    .copied()
                    .unwrap_or_default(),
            ),
            OBSERVED_TRIAL_WALL_MS.load(Ordering::Relaxed),
        )
        .max(MAX_TOPOLOGY_CEILING_MS)
        .to_string()
    }
}

/// ´test:integration:no-test-hardcodes-the-short-trial-ceiling´
#[test]
fn no_test_hardcodes_the_short_trial_ceiling() {
    let source = include_str!("topology.rs");
    let ceiling_literal = ['"', '2', '0', '"'].iter().collect::<String>();
    assert_eq!(
        source.matches(&ceiling_literal).count(),
        1,
        "only ceiling_ms may contain the short ceiling literal"
    );
}

/// ´test:integration:measured-ceiling-scales-with-the-baseline-trial´
#[test]
fn measured_ceiling_scales_with_the_baseline_trial() {
    assert_eq!(ceiling_from_baseline_ms(0), MIN_TOPOLOGY_CEILING_MS);
    assert_eq!(ceiling_from_baseline_ms(50), MIN_TOPOLOGY_CEILING_MS);
    assert_eq!(ceiling_from_baseline_ms(100), MIN_TOPOLOGY_CEILING_MS);
    assert_eq!(ceiling_from_baseline_ms(200), 4_000);
    assert_eq!(ceiling_from_baseline_ms(1_000), 20_000);
    assert_eq!(ceiling_from_baseline_ms(6_000), MAX_TOPOLOGY_CEILING_MS);
    assert_eq!(ceiling_from_baseline_ms(10_000), MAX_TOPOLOGY_CEILING_MS);
}

/// ´test:integration:ceiling-line-carries-the-sample-count-and-standing-sample´
#[test]
fn ceiling_line_carries_the_sample_count_and_standing_sample() {
    assert_eq!(
        ceiling_progress_line(&[120, 305, 210], ceiling_from_baseline_ms(305)),
        "topology-test-ceiling baseline_ms=305 ceiling_ms=6100 samples=3 max_sample_ms=305"
    );
    assert_eq!(
        ceiling_progress_line(&[], MIN_TOPOLOGY_CEILING_MS),
        "topology-test-ceiling baseline_ms=0 ceiling_ms=2000 samples=0 max_sample_ms=0"
    );
}

/// ´test:integration:standing-ceiling-takes-the-larger-of-sample-and-observation´
#[test]
fn standing_ceiling_takes_the_larger_of_sample_and_observation() {
    // PIN: the sample stands alone until an observation exceeds it, the observation takes over when
    // it does, and both readings meet the same floor and the same cap.
    assert_eq!(standing_ceiling_ms(4_000, 0), 4_000);
    assert_eq!(standing_ceiling_ms(4_000, 600), 4_000);
    assert_eq!(standing_ceiling_ms(4_000, 1_000), 4_000);
    assert_eq!(standing_ceiling_ms(4_000, 1_500), 6_000);
    assert_eq!(standing_ceiling_ms(4_000, 90_000), MAX_TOPOLOGY_CEILING_MS);
    assert_eq!(
        standing_ceiling_ms(MAX_TOPOLOGY_CEILING_MS, 90_000),
        MAX_TOPOLOGY_CEILING_MS
    );
    assert_eq!(standing_ceiling_ms(MIN_TOPOLOGY_CEILING_MS, 100), 2_000);
    assert_eq!(standing_ceiling_ms(0, 0), MIN_TOPOLOGY_CEILING_MS);
}

/// ´test:integration:censored-trial-walls-never-raise-the-observed-maximum´
#[test]
fn censored_trial_walls_never_raise_the_observed_maximum() {
    // PIN: a censored wall equals the ceiling by construction, so counting it would raise the
    // ceiling to a multiple of itself on every run that timed a trial out.
    let verdict = json!({
        "trials": [
            {"id": 1, "timed_out": false, "invocation_wall_ms": 120},
            {"id": 2, "timed_out": true, "invocation_wall_ms": 20_000},
            {"id": 3, "timed_out": false, "invocation_wall_ms": 340},
            {"id": 4, "invocation_wall_ms": 40_000},
            {"id": 5, "timed_out": false}
        ]
    });
    assert_eq!(observed_trial_wall_ms(&verdict), 340);
    assert_eq!(observed_trial_wall_ms(&json!({"trials": []})), 0);
    assert_eq!(observed_trial_wall_ms(&json!({})), 0);
    assert_eq!(
        standing_ceiling_ms(4_000, observed_trial_wall_ms(&verdict)),
        4_000
    );
}

/// ´test:integration:censored-ceiling-resample-is-shared-and-cannot-ratchet´
#[test]
fn censored_ceiling_resample_is_shared_and_cannot_ratchet() {
    let resampled = OnceLock::new();
    let calls = AtomicU64::new(0);
    let readers = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                readers.wait();
                assert_eq!(
                    resample_after_censorship(3, &resampled, || {
                        calls.fetch_add(1, Ordering::Relaxed);
                        Ok(ceiling_from_baseline_ms(400))
                    }),
                    Ok(())
                );
            });
        }
    });
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(resampled.get(), Some(&Ok(8_000)));
    assert_eq!(
        resample_after_censorship(300, &resampled, || Ok(MAX_TOPOLOGY_CEILING_MS)),
        Ok(())
    );
    assert_eq!(resampled.get(), Some(&Ok(8_000)));
}

/// ´test:integration:censored-ceiling-resample-requires-boolean-censorship´
#[test]
fn censored_ceiling_resample_requires_boolean_censorship() {
    let resampled = OnceLock::new();
    let verdict = json!({"trials": [
        {"timed_out": false, "invocation_wall_ms": 40_000},
        {"invocation_wall_ms": 40_000},
        {"timed_out": null},
        {"timed_out": "true"}
    ]});
    assert_eq!(censored_trial_count(&verdict), 0);
    assert_eq!(censored_trial_count(&json!({})), 0);
    assert_eq!(
        resample_after_censorship(censored_trial_count(&verdict), &resampled, || Ok(8_000)),
        Ok(())
    );
    assert!(resampled.get().is_none());
    // A censored trial requests measurement even when it has no usable completed wall.
    assert_eq!(
        censored_trial_count(&json!({"trials": [{"timed_out": true}]})),
        1
    );
}

/// ´test:integration:censored-ceiling-resample-caches-failure´
#[test]
fn censored_ceiling_resample_caches_failure() {
    let resampled = OnceLock::new();
    let failure = "sampled trial was censored: baseline-1".to_owned();
    assert_eq!(
        resample_after_censorship(1, &resampled, || Err(failure.clone())),
        Err(failure.clone())
    );
    assert_eq!(
        resample_after_censorship(1, &resampled, || Ok(MAX_TOPOLOGY_CEILING_MS)),
        Err(failure)
    );
}

/// ´test:integration:censored-ceiling-resample-preserves-floor-cap-and-observations´
#[test]
fn censored_ceiling_resample_preserves_floor_cap_and_observations() {
    let original: u64 = 4_000;
    let low_resample = ceiling_from_baseline_ms(50);
    let higher_resample = ceiling_from_baseline_ms(400);
    let capped_resample = ceiling_from_baseline_ms(u64::MAX);
    assert_eq!(standing_ceiling_ms(original.max(low_resample), 0), original);
    assert_eq!(standing_ceiling_ms(original.max(higher_resample), 0), 8_000);
    assert_eq!(
        standing_ceiling_ms(original.max(higher_resample), 3_000),
        12_000
    );
    assert_eq!(
        standing_ceiling_ms(original.max(capped_resample), u64::MAX),
        MAX_TOPOLOGY_CEILING_MS
    );
}

/// ´test:integration:sampled-trial-wall-names-a-missing-field-apart-from-censorship´
#[test]
fn sampled_trial_wall_names_a_missing_field_apart_from_censorship() {
    // PIN: absence, censorship and a field of the wrong type are three separate faults; reading one
    // as another sends the reader to the machine's load when the verdict's shape is what changed,
    // or to a missing field when the field is present and carrying a string or a number.
    assert_eq!(
        sampled_trial_wall_ms(&json!({"id": 1, "timed_out": false, "invocation_wall_ms": 120})),
        Ok(120)
    );
    assert_eq!(
        sampled_trial_wall_ms(&json!({"id": 2, "timed_out": true, "invocation_wall_ms": 20_000})),
        Err("sampled trial was censored: 2".to_owned())
    );
    assert_eq!(
        sampled_trial_wall_ms(&json!({"id": 3, "invocation_wall_ms": 120})),
        Err("the sampled trial reports no timed_out field: 3".to_owned())
    );
    assert_eq!(
        sampled_trial_wall_ms(&json!({"id": 4, "timed_out": null, "invocation_wall_ms": 120})),
        Err("the sampled trial reports no timed_out field: 4".to_owned())
    );
    assert_eq!(
        sampled_trial_wall_ms(&json!({"id": 5, "timed_out": false})),
        Err("the sampled trial reports no invocation wall: 5".to_owned())
    );
    assert_eq!(
        sampled_trial_wall_ms(&json!({"id": 6, "timed_out": "true", "invocation_wall_ms": 120})),
        Err("the sampled trial reports a timed_out field that is not a boolean: 6".to_owned())
    );
    assert_eq!(
        sampled_trial_wall_ms(&json!({"id": 7, "timed_out": 1, "invocation_wall_ms": 120})),
        Err("the sampled trial reports a timed_out field that is not a boolean: 7".to_owned())
    );
}

/// ´test:integration:observed-line-carries-the-wall-and-the-ceiling-it-opens´
#[test]
fn observed_line_carries_the_wall_and_the_ceiling_it_opens() {
    assert_eq!(
        observed_progress_line(1_500),
        "topology-test-ceiling-observed observed_max_ms=1500 observed_ceiling_ms=6000"
    );
    assert_eq!(
        observed_progress_line(0),
        "topology-test-ceiling-observed observed_max_ms=0 observed_ceiling_ms=2000"
    );
}

/// ´test:integration:bypass-assertion-names-the-ceiling-trial´
#[test]
fn bypass_assertion_names_the_ceiling_trial() {
    let (output, verdict) = cached_mode("topology-ceiling");
    let line = censored_non_verdict(
        &verdict,
        &TOPOLOGY_TRIAL_IDS,
        "topology-ceiling",
        &output.stderr,
        "selected_topology",
    )
    .expect("the runtime line names the censored topology trials");
    let expected_trials = verdict["trials"]
        .as_array()
        .expect("trials")
        .iter()
        .filter(|trial| {
            trial["timed_out"] == true && TOPOLOGY_TRIAL_IDS.iter().any(|id| trial["id"] == *id)
        })
        .map(|trial| {
            format!(
                "{}:{}",
                trial["id"].as_str().expect("trial id"),
                trial["permission_mode"].as_str().expect("permission mode")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        line,
        censored_line(
            "topology-ceiling",
            &expected_trials,
            &ceiling_ms("topology-ceiling"),
            "selected_topology"
        )
    );
    let failure = std::panic::catch_unwind(|| assert_bypass_selected(&verdict))
        .expect_err("the ceiling verdict does not select bypass");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .expect("assertion panic has a string message");
    assert!(message.contains("reasons="), "{message}");
    assert!(message.contains("topology-acceptance"), "{message}");
    assert!(
        message.contains(r#""classification_reason":"ceiling""#),
        "{message}"
    );
}

/// ´test:integration:unrelated-ceiling-trial-does-not-censor-topology-or-negative-twin´
#[test]
fn unrelated_ceiling_trial_does_not_censor_topology_or_negative_twin() {
    let verdict = json!({"trials": [
        {"id": "topology-topology-acceptance-1", "timed_out": false},
        {"id": "table-confirmation-native-get-web-fetch-negative-1", "timed_out": false},
        {"id": "table-confirmation-native-read-positive-1", "timed_out": true, "classification_reason": "ceiling"}
    ]});
    let progress = b"probe: start ceiling_ms=500\n";
    assert!(
        censored_non_verdict(
            &verdict,
            &TOPOLOGY_TRIAL_IDS,
            "topology-auto-executed",
            progress,
            "selected_topology",
        )
        .is_none()
    );
    assert!(
        censored_non_verdict(
            &verdict,
            &["table-confirmation-native-get-web-fetch-negative-1"],
            "table-negative-tool-failure",
            progress,
            "censored-negative-trial-classification",
        )
        .is_none()
    );
}

/// # Panics
/// Panics only if the synthetic trial array is malformed or complete acceptance is not censored.
/// ´test:integration:audit-ceiling-censors-selection-with-complete-acceptance´
#[test]
fn audit_ceiling_censors_selection_with_complete_acceptance() {
    let mut audit_verdict = json!({"selected_topology": "blocked", "trials": [{
        "id": "audit-baseline-allow-1", "phase": "audit", "permission_mode": "manual",
        "timed_out": true, "classification_reason": "ceiling"
    }]});
    for phase in ["audit", "bypass", "settings_deny_wins"] {
        audit_verdict["trials"]
            .as_array_mut()
            .expect("trials")
            .push(json!({
                "id": format!("{phase}-completed"), "phase": phase, "timed_out": false,
                "classification_reason": "acceptance-evidence-complete"
            }));
    }
    assert!(assert_bypass_or_censored(
        &audit_verdict,
        b"probe: start ceiling_ms=500\n"
    ));
}

/// # Panics
/// Panics only if a synthetic acceptance ceiling is not reported under its own trial name.
/// ´test:integration:bypass-selection-names-every-acceptance-ceiling´
#[test]
fn bypass_selection_names_every_acceptance_ceiling() {
    for mode in ["topology-auto-refused", "topology-auto-executed"] {
        for phase in ["audit", "bypass", "settings_deny_wins"] {
            for topology_ceiling in [false, true] {
                let id = format!("{phase}-ceiling");
                let mut verdict = json!({"selected_topology": "blocked", "trials": [{
                    "id": id, "phase": phase, "permission_mode": "manual",
                    "timed_out": true, "classification_reason": "ceiling"
                }]});
                if topology_ceiling {
                    verdict["trials"]
                        .as_array_mut()
                        .expect("trials")
                        .push(json!({
                            "id": TOPOLOGY_TRIAL_IDS[0], "phase": "topology",
                            "permission_mode": "auto", "timed_out": true,
                            "classification_reason": "ceiling"
                        }));
                }
                let line = assert_bypass_selection_or_censored(
                    &verdict,
                    b"probe: start ceiling_ms=500\n",
                    mode,
                    "selected_topology,real_hook_classifications,preexisting_reason,trial_count",
                )
                .expect("an acceptance ceiling censors selection");
                assert!(line.contains(&format!("{id}:manual")), "{line}");
                assert!(line.contains(&format!("mode={mode}")), "{line}");
                assert!(line.contains("ceiling_ms=500"), "{line}");
                if topology_ceiling {
                    assert!(line.contains(TOPOLOGY_TRIAL_IDS[0]), "{line}");
                }
            }
        }
    }
}

fn real_hook_ceiling_verdict() -> Value {
    let names = [
        "routine-general",
        "routine-superloop",
        "safe",
        "advanced-read-only",
        "agent-error",
        "suspicious",
        "model-timeout",
        "malformed-model-response",
        "missing-owner-rubric",
        "invalid-owner-rubric",
        "journal-failure",
        "nested-call-guard",
        "general-always-suspicious-owner-match",
        "pre-existing-harness-deny",
    ];
    let mut trials = Vec::new();
    let mut rows = Vec::new();
    for name in names {
        let mut repetitions = Vec::new();
        for repetition in 1..=3 {
            let id = format!("real-hook-{name}-{repetition}");
            let timed_out = name == "routine-general" && repetition == 1;
            repetitions.push(id.clone());
            trials.push(json!({
                "id": id, "phase": "real-hook", "permission_mode": "bypass",
                "repetition": repetition, "timed_out": timed_out,
                "classification_reason": if timed_out { "ceiling" } else { "expected-result" }
            }));
        }
        rows.push(json!({"row": name, "repetitions": repetitions,
            "classification": if name == "routine-general" { "fail" } else { "pass" }}));
    }
    trials.resize(
        (55 + 2 + 44 + 14) * 3,
        json!({"phase": "infrastructure", "timed_out": false}),
    );
    json!({"selected_topology": "bypass", "trials": trials, "real_hook_matrix": rows})
}

/// # Panics
/// Panics only if a real-hook ceiling waives measured selection, shape or completed failures.
/// ´test:integration:real-hook-ceiling-names-waiver-and-retains-completed-failures´
#[test]
fn real_hook_ceiling_names_waiver_and_retains_completed_failures() {
    for mode in ["topology-auto-refused", "topology-auto-executed"] {
        let verdict = real_hook_ceiling_verdict();
        let progress = b"probe: start ceiling_ms=500\n";
        let mut diagnostic = Vec::new();
        let line = assert_real_hook_rows_or_censored_to(&verdict, progress, mode, &mut diagnostic)
            .expect("a real-hook ceiling censors only matrix classifications");
        assert_eq!(
            line,
            format!(
                "topology-test-censored mode={mode} trials=real-hook-routine-general-1:bypass ceiling_ms=500 skipped=real_hook_classifications"
            )
        );
        assert_eq!(
            String::from_utf8(diagnostic).expect("diagnostic"),
            format!("{line}\n")
        );
        assert_selection_details(&verdict, progress, mode, "bypass");
        for (defect, expected) in [
            ("selection", "reasons="),
            ("preexisting", "pre-existing deny row exists"),
            ("prefix", "expected_reason_prefix"),
            ("count", "mode="),
            ("completed", "real-hook-routine-general-2"),
        ] {
            let mut broken = verdict.clone();
            match defect {
                "selection" => broken["selected_topology"] = json!("blocked"),
                "preexisting" => {
                    broken["real_hook_matrix"]
                        .as_array_mut()
                        .expect("matrix")
                        .pop();
                }
                "prefix" => {
                    broken["real_hook_matrix"][13]["expected_reason_prefix"] = json!("unexpected");
                }
                "count" => {
                    broken["trials"].as_array_mut().expect("trials").pop();
                }
                "completed" => broken["trials"][1]["classification_reason"] = json!("tool-failure"),
                _ => unreachable!("fixture defect"),
            }
            let failure = std::panic::catch_unwind(|| {
                assert_selection_details(&broken, progress, mode, "bypass");
            })
            .expect_err("a real-hook ceiling cannot waive measured evidence");
            let message = failure
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| failure.downcast_ref::<&str>().copied())
                .expect("panic text");
            assert!(message.contains(expected), "{defect}: {message}");
        }
    }
}

/// # Panics
/// Panics only if a real-hook timeout with output overflow is waived or misnamed.
/// ´test:integration:real-hook-nonceiling-timeout-refuses-censorship´
#[test]
fn real_hook_nonceiling_timeout_refuses_censorship() {
    let mut verdict = real_hook_ceiling_verdict();
    verdict["trials"][0]["classification_reason"] = json!("output-overflow");
    let failure = std::panic::catch_unwind(|| {
        assert_selection_details(
            &verdict,
            b"probe: start ceiling_ms=500\n",
            "topology-auto-executed",
            "bypass",
        );
    })
    .expect_err("output overflow is not a ceiling waiver");
    assert_eq!(
        failure.downcast_ref::<String>().expect("panic text"),
        "topology-test-timeout: trial=real-hook-routine-general-1 reason=output-overflow cannot censor real_hook_classifications"
    );
}

/// # Panics
/// Panics only if an acceptance failure is censored or its diagnostic omits the failing trial.
/// ´test:integration:audit-ceiling-never-censors-acceptance-failure´
#[test]
fn audit_ceiling_never_censors_acceptance_failure() {
    for (phase, timed_out, reason) in [
        ("audit", false, "wrong-decision"),
        ("bypass", false, "wrong-decision"),
        ("settings_deny_wins", false, "wrong-decision"),
        ("bypass", true, "output-overflow"),
        ("settings_deny_wins", true, "output-overflow"),
    ] {
        let failed_id = format!("{phase}-{reason}");
        let verdict = json!({"selected_topology": "blocked", "trials": [
            {"id": "audit-baseline-allow-1", "phase": "audit", "permission_mode": "manual",
             "timed_out": true, "classification_reason": "ceiling"},
            {"id": failed_id, "phase": phase, "timed_out": timed_out,
             "classification_reason": reason}
        ]});
        let failure = std::panic::catch_unwind(|| {
            assert_bypass_or_censored(&verdict, b"probe: start ceiling_ms=500\n")
        })
        .expect_err("an audit ceiling cannot waive an acceptance failure");
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .expect("assertion panic has a string message");
        assert!(message.contains(&failed_id), "{message}");
        assert!(message.contains(reason), "{message}");
        let diagnostic = if timed_out {
            "topology-test-timeout:"
        } else {
            "acceptance trial failed:"
        };
        assert!(message.contains(diagnostic), "{message}");
    }
}

/// # Panics
/// Panics only if complete acceptance does not require bypass despite a topology ceiling.
/// ´test:integration:topology-ceiling-preserves-completed-acceptance-selection´
#[test]
fn topology_ceiling_preserves_completed_acceptance_selection() {
    let mut verdict = json!({"selected_topology": "bypass", "trials": [{
        "id": TOPOLOGY_TRIAL_IDS[0], "phase": "topology", "permission_mode": "auto",
        "timed_out": true, "classification_reason": "ceiling"
    }]});
    for phase in ["audit", "bypass", "settings_deny_wins"] {
        verdict["trials"]
            .as_array_mut()
            .expect("trials")
            .push(json!({
                "id": format!("{phase}-completed"), "phase": phase, "timed_out": false,
                "classification_reason": "acceptance-evidence-complete"
            }));
    }
    let progress = b"probe: start ceiling_ms=500\n";
    assert!(!assert_bypass_or_censored(&verdict, progress));
    verdict["selected_topology"] = json!("blocked");
    let failure = std::panic::catch_unwind(|| assert_bypass_or_censored(&verdict, progress))
        .expect_err("a topology ceiling cannot waive a fully determined selection");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .expect("assertion panic has a string message");
    assert!(message.contains("timed_out_trials="), "{message}");
    assert!(message.contains("blocked"), "{message}");
}

/// # Panics
/// Panics only if a topology-only ceiling waives measured selection or real-hook evidence.
/// ´test:integration:topology-only-ceiling-keeps-real-hook-assertions´
#[test]
fn topology_only_ceiling_keeps_real_hook_assertions() {
    let mut trials = vec![json!({
        "id": TOPOLOGY_TRIAL_IDS[0], "phase": "topology", "permission_mode": "auto",
        "timed_out": true, "classification_reason": "ceiling"
    })];
    for phase in ["audit", "bypass", "settings_deny_wins"] {
        trials.push(json!({
            "id": format!("{phase}-completed"), "phase": phase, "timed_out": false,
            "classification_reason": "acceptance-evidence-complete"
        }));
    }
    trials.resize(
        (55 + 2 + 44 + 14) * 3,
        json!({"phase": "real-hook", "timed_out": false}),
    );
    let mut verdict = json!({
        "selected_topology": "bypass", "trials": trials,
        "real_hook_matrix": [{"row": "pre-existing-harness-deny", "classification": "pass"}]
    });
    let progress = b"probe: start ceiling_ms=500\n";
    for mode in ["topology-auto-refused", "topology-auto-executed"] {
        let mut diagnostic = Vec::new();
        let line = assert_bypass_selection_or_censored_to(
            &verdict,
            progress,
            mode,
            "selected_topology,real_hook_classifications,preexisting_reason,trial_count",
            &mut diagnostic,
        );
        assert!(
            line.is_none(),
            "measured selection must not produce a skipped line: {line:?}"
        );
        assert!(
            diagnostic.is_empty(),
            "no skipped line may be emitted: {diagnostic:?}"
        );
        assert_selection_details(&verdict, progress, mode, "bypass");
        verdict["real_hook_matrix"][0]["classification"] = json!("fail");
        let failure = std::panic::catch_unwind(|| {
            assert_selection_details(&verdict, progress, mode, "bypass");
        })
        .expect_err("the caller must execute its real-hook assertions");
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .expect("assertion panic has a string message");
        assert!(message.contains("real_hook_rows="), "{message}");
        verdict["real_hook_matrix"][0]["classification"] = json!("pass");
    }
}

/// ´test:integration:dependent-nonceiling-timeout-refuses-censorship´
#[test]
fn dependent_nonceiling_timeout_refuses_censorship() {
    let verdict = json!({"trials": [
        {"id": TOPOLOGY_TRIAL_IDS[0], "timed_out": true, "classification_reason": "ceiling"},
        {"id": TOPOLOGY_TRIAL_IDS[1], "timed_out": true, "classification_reason": "harness-error"}
    ]});
    let progress = format!(
        "probe: start ceiling_ms={}\n",
        ceiling_ms("topology-ceiling")
    );
    let failure = std::panic::catch_unwind(|| {
        censored_non_verdict(
            &verdict,
            &TOPOLOGY_TRIAL_IDS,
            "topology-auto-executed",
            progress.as_bytes(),
            "selected_topology",
        )
    })
    .expect_err("a dependent timeout with another reason cannot be censored");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .expect("assertion panic has a string message");
    assert!(message.contains("topology-test-timeout"), "{message}");
    assert!(message.contains(TOPOLOGY_TRIAL_IDS[1]), "{message}");
    assert!(message.contains("harness-error"), "{message}");
}

fn progress_total(line: &str, prefix: &str) -> usize {
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("terminal progress line has {prefix}"))
        .parse()
        .unwrap_or_else(|_| panic!("terminal progress {prefix} value is an integer"))
}

fn checked_progress_totals(terminal: &str, verdict: &Value) -> (usize, usize) {
    let reported_trials = progress_total(terminal, "trials=");
    let reported_skipped = progress_total(terminal, "skipped=");
    let verdict_trials = verdict["trials"].as_array().expect("trials").len();
    let planned_trials = usize::try_from(
        verdict["planned_trials"]
            .as_u64()
            .expect("planned trials is an integer"),
    )
    .expect("planned trials fits usize");
    assert_eq!(reported_trials, verdict_trials);
    assert_eq!(
        reported_skipped,
        planned_trials
            .checked_sub(verdict_trials)
            .expect("completed trials do not exceed planned trials")
    );
    (reported_trials, reported_skipped)
}

fn checked_full_progress_totals(terminal: &str, verdict: &Value) -> (usize, usize) {
    assert_eq!(verdict["planned_trials"], 345);
    checked_progress_totals(terminal, verdict)
}

/// ´test:integration:checked-progress-totals-agree-with-supplied-verdict-counts´
#[test]
fn checked_progress_totals_agree_with_supplied_verdict_counts() {
    let verdict = json!({
        "planned_trials": 3,
        "trials": [{"id": 1}, {"id": 2}],
    });
    assert_eq!(
        checked_progress_totals("probe: elapsed_s=1 complete trials=2 skipped=1", &verdict),
        (2, 1)
    );
}

/// ´test:integration:repository-probes-use-no-optional-locks´
#[test]
fn repository_probes_use_no_optional_locks() {
    let source = include_str!("topology.rs");
    let tracked_start = ["fn git_", "tracked_paths"].concat();
    let object_store_start = ["fn object_store_", "entries"].concat();
    let snapshot_probes = source
        .split_once(&tracked_start)
        .expect("tracked-path probe exists")
        .1
        .split_once(&object_store_start)
        .expect("object-store probe follows Git probes")
        .0;
    assert_eq!(snapshot_probes.matches("repository_git_output(").count(), 5);

    let helper_start = ["fn repository_", "git_output"].concat();
    let helper = source
        .split_once(&helper_start)
        .expect("repository Git helper exists")
        .1
        .split_once(&tracked_start)
        .expect("Git probes follow repository Git helper")
        .0;
    assert!(helper.contains("--no-optional-locks"));
    assert!(helper.contains("if !output.status.success()"));
    assert!(helper.contains("output = run()"));
}

fn run_mode(mode: &str) -> (FixtureDirectory, Output, Value) {
    run_mode_with_ceiling(mode, ceiling_ms(mode))
}

fn run_mode_with_ceiling(mode: &str, ceiling: String) -> (FixtureDirectory, Output, Value) {
    let directory = FixtureDirectory::new(mode);
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let harness = install_fake_harness(&root, true);
    let verdict = root.join("verdict.json");
    let output = topology_command(&root, &home)
        .args([
            "--verdict",
            verdict.to_str().expect("verdict path is UTF-8"),
        ])
        .env("PERMISSION_TRIAGE_HARNESS_BIN", &harness)
        .env("PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS", ceiling)
        .env("FAKE_HARNESS_MODE", mode)
        .output_serialized()
        .expect("topology binary exits");
    let value =
        serde_json::from_slice(&fs::read(verdict).expect("topology verdict document is written"))
            .expect("topology verdict document is JSON");
    record_observed_walls(&value);
    (directory, output, value)
}

// Share completed immutable evidence; callers that inspect or mutate fixture files use run_mode.
// The producing fixture is dropped before publication, so no cached process or directory survives.
type CachedProbe = (Output, Value);
type ProbeCell = std::sync::Arc<OnceLock<CachedProbe>>;

fn cached_probe(mode: &str, evidence: bool) -> CachedProbe {
    static PROBES: OnceLock<Mutex<std::collections::BTreeMap<(String, bool), ProbeCell>>> =
        OnceLock::new();
    let cell = PROBES
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry((mode.to_owned(), evidence))
        .or_default()
        .clone();
    cell.get_or_init(|| {
        if evidence {
            let (_directory, output, verdict) = run_evidence_mode(mode);
            (output, verdict)
        } else {
            run_confined_mode(mode, if mode == "wrong-version" { 1 } else { 3 })
        }
    })
    .clone()
}

fn cached_mode(mode: &str) -> CachedProbe {
    cached_probe(mode, false)
}

fn cached_evidence_mode(mode: &str) -> CachedProbe {
    cached_probe(mode, true)
}

fn run_evidence_mode(mode: &str) -> (FixtureDirectory, Output, Value) {
    // These evidence fixtures need completed real processes, not a latency grade.
    // Allow 120 seconds per trial on shared 256-core nodes whose load can exceed
    // 270: an early quiet sample cannot bound later scheduling delays. This is a
    // hang ceiling, not a delay; raw walls and all evidence assertions still apply.
    run_mode_with_ceiling(mode, MAX_TOPOLOGY_CEILING_MS.to_string())
}

/// ´test:integration:real-hook-trials-retain-raw-output-exit-and-separate-walls´
#[test]
fn real_hook_trials_retain_raw_output_exit_and_separate_walls() {
    let (output, verdict) = cached_evidence_mode("topology-auto-executed");
    assert_eq!(output.status.code(), Some(3));
    let trials = verdict["trials"].as_array().expect("trial roster");
    let hooked = trials.iter().filter(|trial| trial["phase"] == "real-hook");
    assert_eq!(hooked.clone().count(), 42);
    for trial in hooked {
        let bytes = trial["hook_stdout"]
            .as_array()
            .expect("raw hook stdout is captured, including an empty capture");
        let bytes = bytes
            .iter()
            .map(|byte| u8::try_from(byte.as_u64().expect("byte integer")).expect("byte range"))
            .collect::<Vec<_>>();
        let response: Value = serde_json::from_slice(&bytes).expect("structured enforce response");
        assert_eq!(
            response["hookSpecificOutput"]["permissionDecision"],
            trial["hook_response"]["decision"]
        );
        assert_eq!(trial["hook_exit_code"], 0);
        assert_eq!(trial["hook_mode"], "enforce");
        assert!(trial["hook_stderr"].is_array());
        let hook_wall = trial["hook_wall_ms"]
            .as_u64()
            .expect("hook invocation wall");
        let invocation_wall = trial["invocation_wall_ms"].as_u64().expect("harness wall");
        assert!(hook_wall <= invocation_wall);
        assert_eq!(trial["wall_ms"], invocation_wall);
        assert!(trial["journal_events"].is_array());
    }
}

fn accepted_fake_harness_modes(source: &str) -> BTreeSet<&str> {
    let mut case_depth = 0;
    let mut mode_case_depths = Vec::new();
    let mut modes = BTreeSet::new();
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("case ") && line.ends_with(" in") {
            case_depth += 1;
            if line == r#"case "$mode" in"# {
                mode_case_depths.push(case_depth);
            }
            continue;
        }
        if line == "esac" {
            if mode_case_depths.last() == Some(&case_depth) {
                mode_case_depths.pop();
            }
            case_depth -= 1;
            continue;
        }
        if mode_case_depths.is_empty() {
            continue;
        }
        let Some((patterns, _body)) = line.split_once(')') else {
            continue;
        };
        for mode in patterns.split('|') {
            if mode != "*"
                && mode
                    .chars()
                    .all(|value| value.is_ascii_alphanumeric() || value == '-')
            {
                modes.insert(mode);
            }
        }
    }
    modes
}

fn driven_fake_harness_modes(source: &str) -> BTreeSet<&str> {
    let call_prefixes = [
        r#"run_mode(""#,
        r#"cached_mode(""#,
        r#"cached_evidence_mode(""#,
        r#"assert_selection_outcome(""#,
        r#"assert_probe_confinement(""#,
        r#"run_evidence_mode(""#,
        r#"run_roster_mode(""#,
        r#"assert_topology_disqualifier(""#,
        r#"assert_required_fault(""#,
        r#"assert_registration_fault(""#,
        r#".env("FAKE_HARNESS_MODE", ""#,
    ];
    let mut modes = BTreeSet::new();
    for line in source.lines() {
        for &prefix in &call_prefixes {
            if let Some(mode) = line
                .split_once(prefix)
                .and_then(|(_before, after)| after.split('"').next())
                .filter(|mode| !mode.is_empty() && !mode.contains(')'))
            {
                modes.insert(mode);
            }
        }
        if let Some((mode, remainder)) = line
            .trim()
            .strip_prefix("(\"")
            .and_then(|after| after.split_once('"'))
            && [", 0", ", 1", ", 2", ", 3"]
                .iter()
                .any(|prefix| remainder.starts_with(prefix))
        {
            modes.insert(mode);
        }
    }
    for after in source.split("assert_required_fault(").skip(1) {
        if let Some(mode) = after
            .trim_start()
            .strip_prefix('"')
            .and_then(|after| after.split('"').next())
            .filter(|mode| {
                !mode.is_empty()
                    && mode
                        .chars()
                        .all(|value| value.is_ascii_alphanumeric() || value == '-')
            })
        {
            modes.insert(mode);
        }
    }
    for after in source.split("assert_registration_fault(").skip(1) {
        if let Some(mode) = after
            .trim_start()
            .strip_prefix('"')
            .and_then(|after| after.split('"').next())
            .filter(|mode| {
                !mode.is_empty()
                    && mode
                        .chars()
                        .all(|value| value.is_ascii_alphanumeric() || value == '-')
            })
        {
            modes.insert(mode);
        }
    }

    modes
}

fn assert_fake_blocked(output: &Output, verdict: &Value) {
    assert_eq!(output.status.code(), Some(3), "{}", verdict["reasons"]);
    assert_eq!(verdict["deployment_blocked"], true);
    assert!(
        verdict["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("harness: fake"))
    );
}

fn assert_bypass_selected(verdict: &Value) {
    let timed_out = verdict["trials"]
        .as_array()
        .expect("trials")
        .iter()
        .filter(|trial| trial["timed_out"] == true)
        .collect::<Vec<_>>();
    assert_eq!(
        verdict["selected_topology"],
        "bypass",
        "reasons={}\ntimed_out_trials={}",
        verdict["reasons"],
        serde_json::to_string(&timed_out).expect("timed out trials serialize")
    );
}

const TOPOLOGY_TRIAL_IDS: [&str; 3] = [
    "topology-topology-acceptance-1",
    "topology-topology-acceptance-2",
    "topology-topology-acceptance-3",
];

fn censored_line(mode: &str, names: &str, ceiling: &str, skipped: &str) -> String {
    format!(
        "topology-test-censored mode={mode} trials={names} ceiling_ms={ceiling} skipped={skipped}"
    )
}

/// Build a non-verdict only for ceiling-censored trials read by the named assertion.
fn censored_non_verdict_line(
    verdict: &Value,
    dependent_ids: &[&str],
    mode: &str,
    progress: &[u8],
    skipped: &str,
) -> Option<String> {
    let timed_out = verdict["trials"]
        .as_array()
        .expect("trials")
        .iter()
        .filter(|trial| {
            trial["timed_out"] == true && dependent_ids.iter().any(|id| trial["id"] == *id)
        })
        .collect::<Vec<_>>();
    for trial in &timed_out {
        let id = trial["id"].as_str().expect("trial id is a string");
        let reason = trial["classification_reason"].as_str().unwrap_or("missing");
        assert!(
            reason == "ceiling",
            "topology-test-timeout: trial={id} reason={reason} cannot censor {skipped}"
        );
    }
    if timed_out.is_empty() {
        return None;
    }
    let progress = String::from_utf8_lossy(progress);
    let ceiling = progress
        .split_whitespace()
        .find_map(|field| field.strip_prefix("ceiling_ms="))
        .expect("probe progress names its applied ceiling");
    let names = timed_out
        .iter()
        .map(|trial| {
            format!(
                "{}:{}",
                trial["id"].as_str().expect("trial id is a string"),
                trial["permission_mode"]
                    .as_str()
                    .expect("permission mode is a string")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Some(censored_line(mode, &names, ceiling, skipped))
}

/// Print a waiver only when a real verdict leaves an assertion unmeasured.
fn censored_non_verdict(
    verdict: &Value,
    dependent_ids: &[&str],
    mode: &str,
    progress: &[u8],
    skipped: &str,
) -> Option<String> {
    let line = censored_non_verdict_line(verdict, dependent_ids, mode, progress, skipped)?;
    writeln!(std::io::stderr().lock(), "{line}").expect("censored assertion is printed");
    Some(line)
}

fn assert_completed_topology_trials(verdict: &Value, mode: &str) {
    for trial in verdict["trials"]
        .as_array()
        .expect("trials")
        .iter()
        .filter(|trial| trial["phase"] == "topology")
        .filter(|trial| trial["timed_out"] == false)
    {
        let expected = match mode {
            "topology-auto-refused" if trial["permission_mode"] == "auto" => "refused",
            "topology-prompt" | "topology-changed-command" => "invalid",
            "topology-never-called" => "never-called",
            "mixed" if trial["permission_mode"] == "auto" && trial["repetition"] == 2 => "refused",
            "topology-auto-executed" | "topology-auto-refused" | "mixed" => "executed",
            "topology-ceiling" => panic!("a ceiling-mode topology trial completed: {trial}"),
            _ => panic!("unexpected topology mode: {mode}"),
        };
        assert_eq!(
            trial["classification"], expected,
            "mode={mode} trial={trial}"
        );
    }
}

fn assert_bypass_or_censored(verdict: &Value, progress: &[u8]) -> bool {
    assert_bypass_selection_or_censored(
        verdict,
        progress,
        "topology-auto-executed",
        "selected_topology",
    )
    .is_some()
}

fn assert_bypass_selection_or_censored(
    verdict: &Value,
    progress: &[u8],
    mode: &str,
    skipped: &str,
) -> Option<String> {
    assert_bypass_selection_or_censored_to(
        verdict,
        progress,
        mode,
        skipped,
        &mut std::io::stderr().lock(),
    )
}

fn assert_bypass_selection_or_censored_to(
    verdict: &Value,
    progress: &[u8],
    mode: &str,
    skipped: &str,
    diagnostic: &mut impl std::io::Write,
) -> Option<String> {
    assert_completed_topology_trials(verdict, mode);
    let mut dependent_ids = TOPOLOGY_TRIAL_IDS.to_vec();
    dependent_ids.extend(
        verdict["trials"]
            .as_array()
            .expect("trials")
            .iter()
            .filter(|trial| {
                matches!(
                    trial["phase"].as_str(),
                    Some("audit" | "bypass" | "settings_deny_wins")
                )
            })
            .map(|trial| trial["id"].as_str().expect("acceptance trial id")),
    );
    let censored = censored_non_verdict_line(verdict, &dependent_ids, mode, progress, skipped);
    let mut acceptance_timed_out = false;
    if censored.is_some() {
        for trial in verdict["trials"]
            .as_array()
            .expect("trials")
            .iter()
            .filter(|trial| {
                matches!(
                    trial["phase"].as_str(),
                    Some("audit" | "bypass" | "settings_deny_wins")
                )
            })
        {
            let expected = if trial["timed_out"] == true {
                acceptance_timed_out = true;
                "ceiling"
            } else {
                "acceptance-evidence-complete"
            };
            assert_eq!(
                trial["classification_reason"], expected,
                "acceptance trial failed: {trial}"
            );
        }
    }
    if censored.is_none() || !acceptance_timed_out {
        assert_bypass_selected(verdict);
        return None;
    }
    if let Some(line) = &censored {
        writeln!(diagnostic, "{line}").expect("censored assertion is printed");
    }
    censored
}

fn assert_common_verdict(value: &Value) {
    assert!(
        value["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("harness: fake"))
    );
    assert_eq!(value["schema"], 2);
    assert_eq!(value["supported_harness_version"], "2.1.258");
    assert_eq!(value["harness_version"], "2.1.258");
    assert_eq!(
        value["table_confirmation"]
            .as_array()
            .expect("table confirmation is an array")
            .len(),
        22
    );
    assert!(
        value["table_confirmation"]
            .as_array()
            .expect("table confirmation is an array")
            .iter()
            .all(|row| matches!(
                row["classification"].as_str(),
                Some("candidate" | "fail" | "not-run")
            ))
    );
}

/// ´test:integration:topology-progress-is-complete-and-verdict-only-uses-stdout´
#[test]
fn topology_progress_is_complete_and_verdict_only_uses_stdout() {
    let directory = FixtureDirectory::new("progress");
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let harness = install_fake_harness(&root, true);
    let output = topology_command(&root, &home)
        .env("PERMISSION_TRIAGE_HARNESS_BIN", harness)
        .env(
            "PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS",
            ceiling_ms("topology-auto-executed"),
        )
        .env("FAKE_HARNESS_MODE", "topology-auto-executed")
        .output_serialized()
        .expect("topology binary reports progress");

    assert_eq!(output.status.code(), Some(3));
    let verdict = recorded_stdout_verdict(&output.stdout, "standard output is JSON");
    assert_fake_blocked(&output, &verdict);
    assert_bypass_or_censored(&verdict, &output.stderr);
    assert_eq!(
        verdict["version_cwd"],
        root.parent()
            .expect("fixture root has a parent")
            .to_str()
            .expect("version cwd is UTF-8")
    );
    let mut expected_stdout =
        serde_json::to_vec_pretty(&verdict).expect("verdict serializes identically");
    expected_stdout.push(b'\n');
    assert_eq!(output.stdout, expected_stdout);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("probe:"));

    let progress = String::from_utf8(output.stderr).expect("progress is UTF-8");
    let lines = progress.lines().collect::<Vec<_>>();
    let terminal = lines.last().copied().expect("terminal progress line");
    let (reported_trials, _reported_skipped) = checked_full_progress_totals(terminal, &verdict);
    let trials = verdict["trials"].as_array().expect("trials is an array");
    let table_confirmation = verdict["table_confirmation"]
        .as_array()
        .expect("table confirmation is an array");
    let real_hook_matrix = verdict["real_hook_matrix"]
        .as_array()
        .expect("real hook matrix is an array");
    let fixed_phase_lines = table_confirmation.len()
        + real_hook_matrix.len()
        + ["audit", "bypass", "settings_deny_wins", "infrastructure"]
            .iter()
            .map(|phase| verdict[phase].as_array().expect("required rows").len())
            .sum::<usize>()
        + 4;
    assert_eq!(lines.len(), trials.len() + fixed_phase_lines);
    assert!(
        lines
            .iter()
            .all(|line| line.starts_with("probe: elapsed_s="))
    );
    let trial_lines = lines
        .iter()
        .filter(|line| line.contains(" trial "))
        .collect::<Vec<_>>();
    assert_eq!(trial_lines.len(), reported_trials);
    assert!(trial_lines.iter().all(|line| {
        line.contains(" phase=")
            && line.contains(" name=")
            && line.contains(" polarity=")
            && line.contains(" repetition=")
            && line.contains(" classification=")
            && line.contains(" marker=")
            && line.contains(" capture=")
            && line.contains(" denial_count=")
            && line.contains(" wall_ms=")
    }));
    assert!(trial_lines.iter().all(|line| {
        line.contains("phase=table-confirmation")
            .then(|| line.contains("polarity=positive") || line.contains("polarity=negative"))
            != Some(false)
    }));
    assert!(
        trial_lines
            .iter()
            .filter(|line| line.contains("phase=table-confirmation"))
            .all(|line| line.contains(" marker=n/a"))
    );
    assert!(lines.first().is_some_and(|line| {
        line.contains(" start ")
            && line.contains(" fixture_root=")
            && line.contains(" harness=")
            && line.contains(" ceiling_ms=")
            && line.contains("planned_trials=345")
            && line.contains("topology_trials=6")
            && line.contains("table_confirmation_trials=132")
            && line.contains("real_hook_trials=42")
    }));
    assert!(lines.get(1).is_some_and(|line| {
        line.contains(" version ") && line.contains("version=2.1.258") && line.contains("wall_ms=")
    }));
    assert!(
        terminal.contains(" complete ")
            && terminal.contains(" total_wall_ms=")
            && terminal.contains("status=blocked")
            && terminal.contains("verdict=stdout")
    );
}

/// ´test:integration:closed-progress-pipe-preserves-verdict-and-exit-status´
#[test]
fn closed_progress_pipe_preserves_verdict_and_exit_status() {
    let directory = FixtureDirectory::new("closed-progress-pipe");
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let harness = install_fake_harness(&root, true);
    let mut child = topology_command(&root, &home)
        .env("PERMISSION_TRIAGE_HARNESS_BIN", harness)
        .env(
            "PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS",
            ceiling_ms("topology-auto-executed"),
        )
        .env("FAKE_HARNESS_MODE", "topology-auto-executed")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_serialized()
        .expect("topology binary starts with piped progress");
    let mut progress = BufReader::new(child.stderr.take().expect("progress pipe is available"));
    let mut first_line = String::new();
    progress
        .read_line(&mut first_line)
        .expect("the first progress line is readable");
    assert!(first_line.starts_with("probe: elapsed_s="));
    drop(progress);

    let output = child
        .wait_with_output()
        .expect("topology binary survives the closed progress pipe");
    assert_eq!(output.status.code(), Some(3));
    let verdict = recorded_stdout_verdict(&output.stdout, "verdict remains on stdout");
    assert_common_verdict(&verdict);
    assert_bypass_or_censored(&verdict, first_line.as_bytes());
    let censored_verdict = json!({"trials": [
        {"id": TOPOLOGY_TRIAL_IDS[0], "phase": "topology", "permission_mode": "auto", "timed_out": true, "classification_reason": "ceiling"}
    ]});
    let line = censored_non_verdict_line(
        &censored_verdict,
        &TOPOLOGY_TRIAL_IDS,
        "topology-auto-executed",
        first_line.as_bytes(),
        "selected_topology",
    )
    .expect("a ceiling-censored trial yields a non-verdict");
    let first_ceiling = first_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("ceiling_ms="))
        .expect("the saved progress line names the applied ceiling");
    assert_eq!(
        line,
        censored_line(
            "topology-auto-executed",
            &format!("{}:auto", TOPOLOGY_TRIAL_IDS[0]),
            first_ceiling,
            "selected_topology"
        )
    );
    assert_eq!(verdict["deployment_blocked"], true);
}

fn assert_selection_outcome(mode: &str, status: i32, topology: &str, blocked: bool) {
    let (output, value) = cached_mode(mode);
    assert_eq!(output.status.code(), Some(status), "mode={mode}");
    assert_eq!(output.stdout, [] as [u8; 0], "mode={mode}");
    assert!(
        String::from_utf8_lossy(&output.stderr).starts_with("probe: elapsed_s="),
        "mode={mode}"
    );
    assert_common_verdict(&value);
    assert_completed_topology_trials(&value, mode);
    assert_eq!(value["deployment_blocked"], blocked, "mode={mode}");
    assert_eq!(
        value["real_hook_matrix"]
            .as_array()
            .expect("real hook matrix is an array")
            .len(),
        14,
        "mode={mode}"
    );
    assert_selection_details(&value, &output.stderr, mode, topology);
}

fn assert_real_hook_rows_or_censored_to(
    value: &Value,
    progress: &[u8],
    mode: &str,
    diagnostic: &mut impl std::io::Write,
) -> Option<String> {
    let trials = value["trials"].as_array().expect("trials");
    let dependent_ids = trials
        .iter()
        .filter(|trial| trial["phase"] == "real-hook" && trial["timed_out"] == true)
        .map(|trial| trial["id"].as_str().expect("real-hook trial id"))
        .collect::<Vec<_>>();
    let censored = censored_non_verdict_line(
        value,
        &dependent_ids,
        mode,
        progress,
        "real_hook_classifications",
    );
    if let Some(line) = &censored {
        for trial in trials
            .iter()
            .filter(|trial| trial["phase"] == "real-hook" && trial["timed_out"] != true)
        {
            assert_eq!(
                trial["classification_reason"], "expected-result",
                "completed real-hook trial failed: {trial}"
            );
        }
        writeln!(diagnostic, "{line}").expect("censored assertion is printed");
    } else {
        let real_hook_rows = value["real_hook_matrix"]
            .as_array()
            .expect("real hook matrix");
        assert!(
            real_hook_rows
                .iter()
                .all(|row| row["classification"] == "pass"),
            "mode={mode} real_hook_rows={real_hook_rows:?}"
        );
    }
    censored
}

fn assert_selection_details(value: &Value, progress: &[u8], mode: &str, topology: &str) {
    let skipped = if topology == "blocked" {
        "selected_topology,table_not_run_lines,real_hook_not_run_lines,real_hook_fail_lines,trial_count,terminal_progress"
    } else {
        "selected_topology,real_hook_classifications,preexisting_reason,trial_count"
    };
    if topology == "bypass" {
        if assert_bypass_selection_or_censored(value, progress, mode, skipped).is_some() {
            return;
        }
    } else if mode != "topology-ceiling"
        && censored_non_verdict(value, &TOPOLOGY_TRIAL_IDS, mode, progress, skipped).is_some()
    {
        return;
    }
    assert_eq!(value["selected_topology"], topology, "mode={mode}");
    if topology == "blocked" {
        let progress = String::from_utf8_lossy(progress);
        let table_rows = value["table_confirmation"]
            .as_array()
            .expect("table confirmation is an array");
        let real_hook_rows = value["real_hook_matrix"]
            .as_array()
            .expect("real hook matrix is an array");
        let table_not_run_lines = progress
            .lines()
            .filter(|line| {
                line.contains(" table-confirmation member=") && line.contains("result=not-run")
            })
            .count();
        let not_run_lines = progress
            .lines()
            .filter(|line| line.contains(" real-hook row=") && line.contains("result=not-run"))
            .count();
        assert_eq!(table_not_run_lines, table_rows.len(), "mode={mode}");
        assert_eq!(not_run_lines, real_hook_rows.len(), "mode={mode}");
        assert!(
            !progress
                .lines()
                .any(|line| { line.contains(" real-hook row=") && line.contains("result=fail") })
        );
        let trials = value["trials"].as_array().expect("trials is an array");
        assert_eq!(trials.len(), (55 + 2) * 3, "mode={mode}");
        let skipped = (44 + 14) * 3;
        assert!(progress.lines().last().is_some_and(|line| {
            line.contains(&format!("trials={}", trials.len()))
                && line.contains(&format!("skipped={skipped}"))
                && line.contains("status=blocked")
        }));
    }
    if topology != "blocked" {
        assert_real_hook_rows_or_censored_to(value, progress, mode, &mut std::io::stderr().lock());
        let real_hook_rows = value["real_hook_matrix"]
            .as_array()
            .expect("real hook matrix is an array");
        let preexisting = real_hook_rows
            .iter()
            .find(|row| row["row"] == "pre-existing-harness-deny")
            .expect("pre-existing deny row exists");
        assert!(preexisting.get("expected_reason_prefix").is_none());
        assert_eq!(
            value["trials"]
                .as_array()
                .expect("trials is an array")
                .len(),
            (55 + 2 + 44 + 14) * 3,
            "mode={mode}"
        );
    }
}

/// ´test:integration:selection-topology-auto-refused´
#[test]
fn selection_topology_auto_refused() {
    assert_selection_outcome("topology-auto-refused", 3, "bypass", true);
}

/// ´test:integration:selection-topology-auto-executed´
#[test]
fn selection_topology_auto_executed() {
    assert_selection_outcome("topology-auto-executed", 3, "bypass", true);
}

/// ´test:integration:selection-topology-prompt´
#[test]
fn selection_topology_prompt() {
    assert_selection_outcome("topology-prompt", 3, "blocked", true);
}

/// ´test:integration:selection-topology-changed-command´
#[test]
fn selection_topology_changed_command() {
    assert_selection_outcome("topology-changed-command", 3, "blocked", true);
}

/// ´test:integration:selection-topology-never-called´
#[test]
fn selection_topology_never_called() {
    assert_selection_outcome("topology-never-called", 3, "blocked", true);
}

/// ´test:integration:selection-mixed´
#[test]
fn selection_mixed() {
    assert_selection_outcome("mixed", 3, "blocked", true);
}

/// ´test:integration:selection-topology-ceiling´
#[test]
fn selection_topology_ceiling() {
    assert_selection_outcome("topology-ceiling", 3, "blocked", true);
}

/// ´test:integration:every-fake-harness-mode-is-driven-by-a-test´
#[test]
fn every_fake_harness_mode_is_driven_by_a_test() {
    let harness = std::str::from_utf8(FAKE_HARNESS).expect("fake harness is UTF-8");
    let accepted = accepted_fake_harness_modes(harness);
    let driven = driven_fake_harness_modes(include_str!("topology.rs"));
    assert_eq!(
        driven, accepted,
        "\ntest result: BACKLOG-74-FAIL-BEFORE fake-harness-mode-set"
    );
}

/// ´test:integration:disabled-table-rows-are-candidates-and-do-not-block´
#[test]
fn disabled_table_rows_are_candidates_and_do_not_block() {
    let (_directory, output, value) = run_roster_mode("topology-auto-executed", "implemented");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(value["selected_topology"], "bypass");
    assert_eq!(value["deployment_blocked"], true);
    assert!(
        value["table_confirmation"]
            .as_array()
            .expect("table confirmation is an array")
            .iter()
            .all(|row| row["accepted"] == false
                && row["positive_classification"] == "candidate"
                && row["negative_classification"] == "pass"
                && row["classification"] == "candidate")
    );
    assert_eq!(value["reasons"], json!(["harness: fake"]));
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "table-confirmation member=native-read accepted=false positive=candidate negative=pass result=candidate"
    ));
}

/// ´test:integration:table-negative-tool-failure-with-capture-is-a-passing-twin´
#[test]
fn table_negative_tool_failure_with_capture_is_a_passing_twin() {
    let (output, value) = cached_mode("table-negative-tool-failure");
    assert_eq!(output.status.code(), Some(3));
    let trials = value["trials"].as_array().expect("trials are an array");
    let negatives = trials
        .iter()
        .filter(|trial| trial["name"] == "native-get-web-fetch" && trial["polarity"] == "negative")
        .collect::<Vec<_>>();
    assert_eq!(negatives.len(), 3);
    let dependent_ids = [
        "table-confirmation-native-get-web-fetch-negative-1",
        "table-confirmation-native-get-web-fetch-negative-2",
        "table-confirmation-native-get-web-fetch-negative-3",
    ];
    let censored = censored_non_verdict(
        &value,
        &dependent_ids,
        "table-negative-tool-failure",
        &output.stderr,
        "censored-negative-trial-classification,member-classification",
    )
    .is_some();
    for trial in negatives {
        if trial["timed_out"] == true && trial["classification_reason"] == "ceiling" {
            assert!(censored, "censored target trial is reported");
            continue;
        }
        assert_eq!(trial["classification"], "pass");
        assert_eq!(trial["classification_reason"], "model-capture-observed");
        assert_eq!(trial["capture_observed"], true);
        assert_eq!(trial["permission_denials"], json!([]));
        assert_eq!(trial["events"][0]["event"], "PreToolUse");
        assert_eq!(trial["events"][1]["event"], "PostToolUseFailure");
        assert_eq!(
            trial["events"][0]["tool_use_id"],
            trial["events"][1]["tool_use_id"]
        );
    }
    if !censored {
        let member = value["table_confirmation"]
            .as_array()
            .expect("table confirmation is an array")
            .iter()
            .find(|member| member["member"] == "native-get-web-fetch")
            .expect("WebFetch member exists");
        assert_eq!(member["positive_classification"], "candidate");
        assert_eq!(member["negative_classification"], "pass");
        assert_eq!(member["classification"], "candidate");
    }
    assert_eq!(output.status.code(), Some(3));
}

/// ´test:integration:table-negative-tool-failure-without-capture-is-a-failing-twin´
#[test]
fn table_negative_tool_failure_without_capture_is_a_failing_twin() {
    let (output, value) = cached_mode("table-negative-tool-failure-no-capture");
    let trial = value["trials"]
        .as_array()
        .expect("trials are an array")
        .iter()
        .find(|trial| trial["id"] == "table-confirmation-native-get-web-fetch-negative-1")
        .expect("WebFetch negative trial exists");
    assert_eq!(trial["classification"], "fail");
    assert_eq!(trial["classification_reason"], "model-capture-absent");
    assert_eq!(trial["capture_observed"], false);
    let member = value["table_confirmation"]
        .as_array()
        .expect("table confirmation is an array")
        .iter()
        .find(|member| member["member"] == "native-get-web-fetch")
        .expect("WebFetch member exists");
    assert_eq!(member["classification"], "fail");
    assert!(
        value["reasons"]
            .as_array()
            .expect("reasons are an array")
            .iter()
            .any(|reason| reason == "table-confirmation:native-get-web-fetch:failed")
    );
    let later_trial = value["trials"]
        .as_array()
        .expect("trials are an array")
        .iter()
        .find(|trial| trial["id"] == "table-confirmation-bash-pwd-negative-1")
        .expect("later table trial exists");
    assert_eq!(later_trial["capture_observed"], true);
    assert_eq!(output.status.code(), Some(3));
}

/// ´test:integration:real-hook-tool-failure-is-invalid-and-blocking´
#[test]
fn real_hook_tool_failure_is_invalid_and_blocking() {
    let (output, value) = cached_evidence_mode("real-hook-tool-failure");
    assert_eq!(output.status.code(), Some(3));
    let trial = value["trials"]
        .as_array()
        .expect("trials are an array")
        .iter()
        .find(|trial| trial["id"] == "real-hook-routine-general-1")
        .expect("routine-general real-hook trial exists");
    assert_eq!(
        trial["classification"], "invalid",
        "\ntest result: CORRECTION-FAIL-BEFORE real-hook-tool-failure"
    );
    assert_eq!(trial["classification_reason"], "tool-failure");
    let row = value["real_hook_matrix"]
        .as_array()
        .expect("real-hook matrix is an array")
        .iter()
        .find(|row| row["row"] == "routine-general")
        .expect("routine-general matrix row exists");
    assert_eq!(
        row["classification"], "invalid",
        "\ntest result: SECOND-CORRECTION-FAIL-BEFORE real-hook-matrix-invalid-summary"
    );
    assert!(
        value["reasons"]
            .as_array()
            .expect("reasons are an array")
            .iter()
            .any(|reason| reason == "real-hook:routine-general:invalid")
    );
}

/// ´test:integration:deny-expected-real-hook-tool-failure-is-bypass-evidence´
#[test]
fn deny_expected_real_hook_tool_failure_is_bypass_evidence() {
    let (output, value) = cached_mode("real-hook-deny-tool-failure");
    let trial = value["trials"]
        .as_array()
        .expect("trials are an array")
        .iter()
        .find(|trial| trial["id"] == "real-hook-agent-error-1")
        .expect("agent-error real-hook trial exists");
    assert_eq!(trial["classification"], "tool-invoked-despite-deny");
    assert_eq!(trial["classification_reason"], "tool-invoked-despite-deny");
    let row = value["real_hook_matrix"]
        .as_array()
        .expect("real-hook matrix is an array")
        .iter()
        .find(|row| row["row"] == "agent-error")
        .expect("agent-error matrix row exists");
    assert_eq!(row["classification"], "fail");
    assert!(
        value["reasons"]
            .as_array()
            .expect("reasons are an array")
            .iter()
            .any(|reason| reason == "real-hook:agent-error:tool-invoked-despite-deny")
    );
    assert_eq!(output.status.code(), Some(3));
}

/// ´test:integration:deny-row-tool-failure-retains-bypass-reason´
#[test]
fn deny_row_tool_failure_retains_bypass_reason() {
    let (output, value) = cached_mode("real-hook-tool-failure");
    assert_eq!(output.status.code(), Some(3));
    let trial = value["trials"]
        .as_array()
        .expect("trials are an array")
        .iter()
        .find(|trial| trial["id"] == "real-hook-pre-existing-harness-deny-1")
        .expect("pre-existing deny trial exists");
    assert_eq!(
        trial["classification"], "preexisting-deny-bypassed",
        "\ntest result: SECOND-CORRECTION-FAIL-BEFORE deny-row-tool-failure-precedence-in-matrix"
    );
    assert_eq!(trial["classification_reason"], "preexisting-deny-bypassed");
}

/// ´test:integration:model-prose-naming-a-prompt-is-not-prompt-evidence´
#[test]
fn model_prose_naming_a_prompt_is_not_prompt_evidence() {
    let (output, value) = cached_evidence_mode("real-hook-deny-prompt-prose");
    let trial = value["trials"]
        .as_array()
        .expect("trials are an array")
        .iter()
        .find(|trial| trial["id"] == "real-hook-pre-existing-harness-deny-1")
        .expect("pre-existing deny trial exists");
    assert!(
        trial["result"]
            .as_str()
            .expect("the retained result text is a string")
            .contains("approve the permission prompt"),
        "\ntest result: PROMPT-EVIDENCE-FAIL-BEFORE deny-row-result-prose"
    );
    assert_eq!(
        trial["permission_denials"]
            .as_array()
            .expect("permission denials are an array")
            .len(),
        1,
        "\ntest result: PROMPT-EVIDENCE-FAIL-BEFORE deny-row-denial-count"
    );
    assert_eq!(trial["ran"], false);
    assert_eq!(trial["exit_code"], 0);
    assert!(
        trial["events"]
            .as_array()
            .expect("events are an array")
            .iter()
            .all(|event| event["event"] != "PermissionRequest"),
        "\ntest result: PROMPT-EVIDENCE-FAIL-BEFORE deny-row-no-permission-request"
    );
    assert_eq!(
        trial["prompt"], false,
        "\ntest result: PROMPT-EVIDENCE-FAIL-BEFORE deny-row-prompt-condition"
    );
    assert_eq!(
        trial["classification"], "expected-result",
        "\ntest result: PROMPT-EVIDENCE-FAIL-BEFORE deny-row-classification"
    );
    assert_eq!(trial["classification_reason"], "expected-result");
    let row = value["real_hook_matrix"]
        .as_array()
        .expect("real-hook matrix is an array")
        .iter()
        .find(|row| row["row"] == "pre-existing-harness-deny")
        .expect("pre-existing deny matrix row exists");
    assert_eq!(
        row["classification"], "pass",
        "\ntest result: PROMPT-EVIDENCE-FAIL-BEFORE deny-row-matrix-classification"
    );
    assert!(
        value["reasons"]
            .as_array()
            .expect("reasons are an array")
            .iter()
            .all(|reason| reason
                .as_str()
                .is_none_or(|reason| !reason.contains("prompt"))),
        "\ntest result: PROMPT-EVIDENCE-FAIL-BEFORE verdict-carries-no-prompt-reason"
    );
    assert_eq!(value["deployment_blocked"], true);
    assert_eq!(
        output.status.code(),
        Some(3),
        "\ntest result: PROMPT-EVIDENCE-FAIL-BEFORE deny-row-exit-status"
    );
}

/// ´test:integration:every-trial-requests-and-retains-one-json-result-document´
#[test]
fn every_trial_requests_and_retains_one_json_result_document() {
    let (output, value) = cached_evidence_mode("topology-auto-executed");
    assert_eq!(output.status.code(), Some(3));
    let trials = value["trials"].as_array().expect("trials is an array");
    assert_eq!(trials.len(), (55 + 2 + 44 + 14) * 3);
    for trial in trials {
        let argv = trial["argv"].as_array().expect("trial argv is an array");
        let no_session = argv
            .iter()
            .position(|argument| argument == "--no-session-persistence")
            .expect("no-session-persistence argument exists");
        assert_eq!(
            argv.get(no_session + 1),
            Some(&Value::from("--output-format"))
        );
        assert_eq!(argv.get(no_session + 2), Some(&Value::from("json")));
        assert_eq!(trial["result_document_valid"], true, "{trial}");
        assert!(trial["permission_denials"].is_array());
        assert!(trial["result"].is_string());
        assert!(trial["is_error"].is_boolean());
        assert!(trial["num_turns"].is_u64());
    }
}

/// ´test:integration:topology-classifies-executed-refused-and-never-called´
#[test]
fn topology_classifies_executed_refused_and_never_called() {
    let (_output, executed) = cached_mode("topology-auto-executed");
    assert!(topology_trials(&executed).iter().all(|trial| {
        trial["classification"] == "executed"
            && trial["permission_denials"] == json!([])
            && trial["is_error"] == false
            && trial["num_turns"] == 1
    }));

    let (_output, refused) = cached_mode("topology-auto-refused");
    let refused_trials = topology_trials(&refused);
    assert!(refused_trials.iter().any(|trial| {
        trial["permission_mode"] == "auto"
            && trial["classification"] == "refused"
            && trial["permission_denials"].as_array().map(Vec::len) == Some(1)
            && trial["result"] == "fixture refusal"
            && trial["num_turns"] == 2
    }));

    let (_output, never_called) = cached_mode("topology-never-called");
    assert!(topology_trials(&never_called).iter().all(|trial| {
        trial["classification"] == "never-called"
            && trial["classification_reason"] == "no-command-proposed"
    }));
}

fn topology_trials(value: &Value) -> Vec<&Value> {
    value["trials"]
        .as_array()
        .expect("trials is an array")
        .iter()
        .filter(|trial| trial["phase"] == "topology")
        .collect::<Vec<_>>()
}

fn assert_topology_disqualifier(mode: &str, reason: &str) {
    let (output, value) = cached_mode(mode);
    // Two denial documents cannot establish one correlated denial; a denial for another
    // command cannot establish this request's outcome. Both disqualify the manual/AUTO
    // characterization trial. They do not add a bypass failure; fake provenance blocks
    // deployment independently of the required rows and their load-sensitive results.
    assert_fake_blocked(&output, &value);
    assert!(topology_trials(&value).iter().all(|trial| {
        trial["classification"] == "invalid" && trial["classification_reason"] == reason
    }));
}

/// ´test:integration:topology-is-error-disqualifies-before-evidence-classes´
#[test]
fn topology_is_error_disqualifies_before_evidence_classes() {
    assert_topology_disqualifier("topology-is-error", "result-is-error");
}

/// ´test:integration:topology-nonzero-exit-disqualifies-before-evidence-classes´
#[test]
fn topology_nonzero_exit_disqualifies_before_evidence_classes() {
    assert_topology_disqualifier("topology-nonzero", "nonzero-exit");
}

/// ´test:integration:topology-prompt-disqualifies-before-evidence-classes´
#[test]
fn topology_prompt_disqualifies_before_evidence_classes() {
    assert_topology_disqualifier("topology-prompt", "prompt");
}

/// ´test:integration:topology-ceiling-disqualifies-before-evidence-classes´
#[test]
fn topology_ceiling_disqualifies_before_evidence_classes() {
    assert_topology_disqualifier("topology-ceiling", "ceiling");
}

/// Retain the original half-second real wait while other matrices only prove that the cap fires.
/// ´test:integration:topology-ceiling-retains-half-second-real-wait´
#[test]
fn topology_ceiling_retains_half_second_real_wait() {
    let (_directory, output, verdict) = run_mode_with_ceiling("topology-ceiling", 500.to_string());
    assert_eq!(output.status.code(), Some(3));
    let trials = verdict["trials"]
        .as_array()
        .expect("completed trial roster");
    assert_eq!(trials.len(), (55 + 2) * 3);
    for trial in trials {
        assert_eq!(trial["timed_out"], true);
        assert_eq!(trial["classification_reason"], "ceiling");
        assert!(trial["invocation_wall_ms"].as_u64().expect("real wait") >= 500);
    }
    assert_eq!(verdict["selected_topology"], "blocked");
    assert_eq!(verdict["deployment_blocked"], true);
}

/// The production default kills the harness group, including a descendant holding the capture pipe.
/// ´test:integration:actual-production-ceiling-times-out-and-reaps-version-process´
#[test]
fn actual_production_ceiling_times_out_and_reaps_version_process() {
    let directory = FixtureDirectory::new("production-ceiling");
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&root).expect("production ceiling root");
    fs::create_dir(&home).expect("production ceiling HOME");
    let harness = root.join("waiting-harness");
    let pid_path = root.join("waiting.pid");
    write_executable(
        &harness,
        br#"#!/usr/bin/env python3
import os, time
with open(os.environ["TOPOLOGY_PRODUCTION_WAIT_PID"], "w") as f:
    f.write(str(os.getpid()))
child = os.fork()
if child == 0:
    with open(os.environ["TOPOLOGY_PRODUCTION_WAIT_PID"] + ".child", "w") as f:
        f.write(str(os.getpid()))
    # Inherit stdout: killing only the harness must not release the capture reader.
    time.sleep(240)
else:
    time.sleep(240)
"#,
        0o700,
    )
    .expect("real waiting harness");
    // A separate subreaper owns the orphaned descendant, so this assertion does
    // not depend on the node's PID 1 reaping promptly or affect concurrent tests.
    let supervisor = r#"
import ctypes, os, signal, subprocess, sys
assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
result = subprocess.run(sys.argv[1:], check=False)
pid, status = os.waitpid(-1, 0)
assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL, (pid, status)
print("descendant reaped after group SIGKILL", file=sys.stderr)
sys.exit(result.returncode)
"#;
    let probe = topology_command(&root, &home);
    let mut command = Command::new("python3");
    command
        .args(["-c", supervisor])
        .arg(probe.get_program())
        .args(probe.get_args());
    for (name, value) in probe.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        } else {
            command.env_remove(name);
        }
    }
    let started = std::time::Instant::now();
    let output = command
        .env("PERMISSION_TRIAGE_HARNESS_BIN", &harness)
        .env("TOPOLOGY_PRODUCTION_WAIT_PID", &pid_path)
        .output_serialized()
        .expect("production ceiling probe");
    assert!(
        started.elapsed().as_millis()
            >= u128::from(permission_triage::topology::MAX_TOPOLOGY_CEILING_MS)
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "harness --version did not complete successfully within its output and wall limits"
    ));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("descendant reaped after group SIGKILL")
    );
    for path in [pid_path.clone(), pid_path.with_extension("pid.child")] {
        let pid = fs::read_to_string(path).expect("waiting process recorded its pid");
        let pid: u32 = pid.trim().parse().expect("numeric process id");
        assert!(
            !Path::new("/proc").join(pid.to_string()).exists(),
            "timed-out process {pid} was not reaped"
        );
    }
    assert_no_probe_owned_path(&root);
}

/// ´test:integration:topology-changed-command-disqualifies-before-evidence-classes´
#[test]
fn topology_changed_command_disqualifies_before_evidence_classes() {
    assert_topology_disqualifier("topology-changed-command", "changed-command");
}

/// ´test:integration:topology-changed-denial-disqualifies-before-evidence-classes´
#[test]
fn topology_changed_denial_disqualifies_before_evidence_classes() {
    assert_topology_disqualifier("topology-changed-denial", "changed-command");
}

/// ´test:integration:topology-multiple-denials-disqualify-before-evidence-classes´
#[test]
fn topology_multiple_denials_disqualify_before_evidence_classes() {
    assert_topology_disqualifier("topology-multiple-denials", "multiple-denials");
}

/// ´test:integration:topology-unparseable-stdout-disqualifies-before-evidence-classes´
#[test]
fn topology_unparseable_stdout_disqualifies_before_evidence_classes() {
    assert_topology_disqualifier("topology-malformed-output", "unparseable-stdout");
}

/// ´test:integration:multiple-result-documents-are-unparseable-stdout´
#[test]
fn multiple_result_documents_are_unparseable_stdout() {
    assert_topology_disqualifier("topology-multiple-documents", "unparseable-stdout");
}

/// ´test:integration:mixed-execution-and-denial-evidence-is-invalid´
#[test]
fn mixed_execution_and_denial_evidence_is_invalid() {
    assert_topology_disqualifier("topology-both-observations", "evidence-mismatch");
}

/// ´test:integration:table-confirmation-captures-are-unique-cleared-and-polarity-aware´
#[test]
fn table_confirmation_captures_are_unique_cleared_and_polarity_aware() {
    let (directory, output, value) = run_mode("stale-captures");
    assert_eq!(output.status.code(), Some(3));
    let matrix_trials = value["trials"]
        .as_array()
        .expect("trials is an array")
        .iter()
        .filter(|trial| trial["phase"] == "table-confirmation")
        .collect::<Vec<_>>();
    assert_eq!(matrix_trials.len(), 132);
    let mut captures = matrix_trials
        .iter()
        .map(|trial| {
            trial["capture"]
                .as_str()
                .expect("matrix trial capture is retained")
        })
        .collect::<Vec<_>>();
    captures.sort_unstable();
    captures.dedup();
    assert_eq!(captures.len(), matrix_trials.len());

    let positive = matrix_trials
        .iter()
        .find(|trial| trial["id"] == "table-confirmation-native-read-positive-1")
        .expect("first positive matrix trial exists");
    assert_eq!(positive["polarity"], "positive");
    assert_eq!(positive["marker"], "n/a");
    assert_eq!(positive["marker_observed"], Value::Null);
    assert_eq!(positive["capture_observed"], false);
    assert_eq!(positive["classification"], "fail");
    assert_eq!(
        positive["classification_reason"],
        "disabled-entry-capture-absent"
    );
    let retained_settings = fs::read_to_string(
        directory
            .probe_root()
            .join("state/evidence/bypass/table-confirmation-native-read-positive-1/settings.json"),
    )
    .expect("the first stale-capture trial retains its restored settings");
    assert!(retained_settings.contains("real-hook-driver"));

    let negative = matrix_trials
        .iter()
        .find(|trial| trial["id"] == "table-confirmation-native-read-negative-1")
        .expect("first negative matrix trial exists");
    assert_eq!(negative["polarity"], "negative");
    assert_eq!(negative["marker"], "n/a");
    assert_eq!(negative["marker_observed"], Value::Null);
    assert_eq!(negative["capture_observed"], false);
    assert_eq!(negative["classification"], "fail");
    assert!(
        value["reasons"]
            .as_array()
            .expect("reasons is an array")
            .iter()
            .any(|reason| reason == "table-confirmation:native-read:failed")
    );
}

/// ´test:integration:table-confirmation-uses-named-bash-exclusions´
#[test]
fn table_confirmation_uses_named_bash_exclusions() {
    let (_output, value) = cached_mode("topology-auto-executed");
    let trials = value["trials"].as_array().expect("trials is an array");
    let forms = [
        ("bash-pwd", "pwd", "ls ../outside-project.txt"),
        ("bash-ls", "ls readable.txt", "ls ../outside-project.txt"),
        ("bash-stat", "stat readable.txt", "stat /etc/passwd"),
        (
            "bash-file",
            "file readable.txt",
            "file ../outside-project.txt",
        ),
        ("bash-readlink", "readlink link", "readlink ../outside-link"),
        ("bash-wc", "wc readable.txt", "wc ../outside-project.txt"),
        (
            "bash-rg",
            "rg topology readable.txt",
            "rg topology ../outside-project.txt",
        ),
        (
            "bash-grep",
            "grep topology readable.txt",
            "grep topology ../outside-project.txt",
        ),
        (
            "bash-sed-n",
            "sed -n 1p readable.txt",
            "sed -i s/a/b/ readable.txt",
        ),
        (
            "bash-head",
            "head readable.txt",
            "head ../outside-project.txt",
        ),
        (
            "bash-tail",
            "tail readable.txt",
            "tail ../outside-project.txt",
        ),
        (
            "bash-jq",
            "jq .topology data.json",
            "jq .topology ../outside-project.txt",
        ),
        ("bash-git-status", "git status", "git fetch origin"),
        ("bash-git-diff", "git diff", "git add readable.txt"),
        ("bash-git-log", "git log", "git checkout -- readable.txt"),
        (
            "bash-git-show",
            "git show",
            "git commit -m topology-fixture",
        ),
        ("bash-git-rev-parse", "git rev-parse HEAD", "git gc"),
    ];
    for (member, positive, negative) in forms {
        for (polarity, expected) in [("positive", positive), ("negative", negative)] {
            let id = format!("table-confirmation-{member}-{polarity}-1");
            let trial = trials
                .iter()
                .find(|trial| trial["id"] == id)
                .expect("named Bash table trial exists");
            assert_eq!(
                trial["events"][0]["command"], expected,
                "member={member} polarity={polarity}"
            );
        }
    }
}

/// ´test:integration:table-confirmation-has-no-manufactured-markers´
#[test]
fn table_confirmation_has_no_manufactured_markers() {
    let audit_hook = include_str!("topology/bin/audit-hook");
    assert!(!audit_hook.contains("state_root / marker"));
    assert!(!audit_hook.contains(".touch("));
    assert!(!audit_hook.contains(".replace("));

    let (_output, value) = cached_mode("topology-auto-executed");
    assert!(
        value["trials"]
            .as_array()
            .expect("trials is an array")
            .iter()
            .filter(|trial| trial["phase"] == "table-confirmation")
            .all(|trial| trial["marker"] == "n/a"
                && trial["marker_observed"] == Value::Null
                && trial["ran"] == false)
    );
}

/// ´test:integration:table-confirmation-observes-present-captures´
#[test]
fn table_confirmation_observes_present_captures() {
    let (_output, present) = cached_mode("topology-auto-executed");
    let present_trials = present["trials"].as_array().expect("trials is an array");
    for polarity in ["positive", "negative"] {
        assert!(present_trials.iter().any(|trial| {
            trial["phase"] == "table-confirmation"
                && trial["polarity"] == polarity
                && trial["capture_observed"] == true
        }));
    }
}

/// ´test:integration:table-confirmation-observes-absent-captures´
#[test]
fn table_confirmation_observes_absent_captures() {
    let (_output, absent) = cached_mode("stale-captures");
    let absent_trials = absent["trials"].as_array().expect("trials is an array");
    for polarity in ["positive", "negative"] {
        assert!(absent_trials.iter().any(|trial| {
            trial["phase"] == "table-confirmation"
                && trial["polarity"] == polarity
                && trial["capture_observed"] == false
        }));
    }
}

fn ceiling_progress(configured: Option<&str>) -> String {
    let directory = FixtureDirectory::new("ceiling-bounds");
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let harness = install_fake_harness(&root, true);
    let mut command = topology_command(&root, &home);
    command
        .env("PERMISSION_TRIAGE_HARNESS_BIN", harness)
        .env("FAKE_HARNESS_MODE", "wrong-version");
    if let Some(value) = configured {
        command.env("PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS", value);
    }
    let output = command
        .output_serialized()
        .expect("preflight-only topology probe exits");
    assert_eq!(output.status.code(), Some(1));
    String::from_utf8(output.stderr).expect("progress is UTF-8")
}

/// ´test:integration:topology-ceiling-default-cap-and-override-are-bounded´
#[test]
fn topology_ceiling_default_cap_and_override_are_bounded() {
    assert!(ceiling_progress(None).contains("ceiling_ms=120000"));
    assert!(ceiling_progress(Some("240000")).contains("ceiling_ms=120000"));
    assert!(ceiling_progress(Some("1234")).contains("ceiling_ms=1234"));
}

/// ´test:integration:wrong-version-writes-blocked-verdict-and-exits-one´
#[test]
fn wrong_version_writes_blocked_verdict_and_exits_one() {
    let (output, value) = cached_mode("wrong-version");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["harness_version"], "9.9.9");
    assert_eq!(value["selected_topology"], "blocked");
    assert_eq!(value["deployment_blocked"], true);
    assert_eq!(
        value["reasons"],
        serde_json::json!(["unsupported-harness", "harness: fake"])
    );
    assert_eq!(
        value["trials"]
            .as_array()
            .expect("trials is an array")
            .len(),
        0
    );
}

/// ´test:integration:suffix-version-replaces-stale-ready-verdict´
#[test]
fn suffix_version_replaces_stale_ready_verdict() {
    let directory = FixtureDirectory::new("suffix-version");
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let harness = install_fake_harness(&root, true);
    let verdict = root.join("verdict.json");
    fs::write(&verdict, b"{\"selected_topology\":\"auto\"}\n")
        .expect("stale ready verdict is written");

    let output = topology_command(&root, &home)
        .args([
            "--verdict",
            verdict.to_str().expect("verdict path is UTF-8"),
        ])
        .env("PERMISSION_TRIAGE_HARNESS_BIN", harness)
        .env(
            "PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS",
            ceiling_ms("suffix-version"),
        )
        .env("FAKE_HARNESS_MODE", "suffix-version")
        .output_serialized()
        .expect("suffix-version topology probe exits");
    let value: Value = serde_json::from_slice(
        &fs::read(&verdict).expect("blocked suffix-version verdict is written"),
    )
    .expect("blocked suffix-version verdict is JSON");
    record_observed_walls(&value);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["harness_version"], "2.1.258-rc");
    assert_eq!(value["harness_version_output"]["stdout"], "2.1.258-rc\n");
    assert_eq!(value["selected_topology"], "blocked");
    assert_eq!(value["deployment_blocked"], true);
    assert_eq!(
        value["reasons"],
        serde_json::json!(["unsupported-harness", "harness: fake"])
    );
}

/// ´test:integration:atomic-verdict-uses-owned-unique-temporary´
#[test]
fn atomic_verdict_uses_owned_unique_temporary() {
    let directory = FixtureDirectory::new("atomic-verdict");
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let harness = install_fake_harness(&root, true);
    let verdict = root.join("verdict.json");
    fs::write(&verdict, b"previous verdict\n").expect("existing verdict is written");
    let foreign_temporary = root.join(".verdict.json.permission-triage-topology.tmp");
    let foreign_bytes = b"foreign temporary remains intact\n";
    fs::write(&foreign_temporary, foreign_bytes).expect("foreign temporary is created");

    let output = topology_command(&root, &home)
        .args([
            "--verdict",
            verdict.to_str().expect("verdict path is UTF-8"),
        ])
        .env("PERMISSION_TRIAGE_HARNESS_BIN", harness)
        .env(
            "PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS",
            ceiling_ms("topology-auto-executed"),
        )
        .env("FAKE_HARNESS_MODE", "topology-auto-executed")
        .output_serialized()
        .expect("topology binary writes through its unique temporary");

    assert_eq!(
        output.status.code(),
        Some(3),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(&foreign_temporary).expect("foreign temporary is readable"),
        foreign_bytes
    );
    let value: Value = serde_json::from_slice(&fs::read(verdict).expect("new verdict is readable"))
        .expect("new verdict is JSON");
    record_observed_walls(&value);
}

/// ´test:integration:failed-verdict-write-preserves-existing-document´
#[test]
fn failed_verdict_write_preserves_existing_document() {
    let directory = FixtureDirectory::new("failed-verdict-write");
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let harness = install_fake_harness(&root, true);
    let output_directory = root.join("verdict-output");
    fs::create_dir(&output_directory).expect("verdict output directory is created");
    let verdict = output_directory.join("verdict.json");
    let previous = b"previous verdict remains byte-identical\n";
    fs::write(&verdict, previous).expect("previous verdict is written");
    fs::set_permissions(&output_directory, fs::Permissions::from_mode(0o500))
        .expect("verdict output directory becomes owner-read-only");

    let output = topology_command(&root, &home)
        .args([
            "--verdict",
            verdict.to_str().expect("verdict path is UTF-8"),
        ])
        .env("PERMISSION_TRIAGE_HARNESS_BIN", harness)
        .env(
            "PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS",
            ceiling_ms("topology-auto-executed"),
        )
        .env("FAKE_HARNESS_MODE", "topology-auto-executed")
        .output_serialized()
        .expect("topology binary reports the verdict write failure");

    fs::set_permissions(&output_directory, fs::Permissions::from_mode(0o700))
        .expect("verdict output directory mode is restored");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("probe: elapsed_s="));
    assert!(stderr.contains("\nverdict write failed:"));
    assert_eq!(
        fs::read(verdict).expect("previous verdict remains readable"),
        previous
    );
}

fn run_refusal(root: &Path, home: &Path, harness: Option<&Path>) -> Output {
    let mut command = topology_command(root, home);
    if let Some(path) = harness {
        command.env("PERMISSION_TRIAGE_HARNESS_BIN", path);
    }
    command.output_serialized().expect("refusal probe exits")
}

fn assert_no_probe_owned_path(root: &Path) {
    for path in [
        "settings.json",
        "bin",
        "state",
        "project",
        "outside-project.txt",
        "outside-link",
    ] {
        assert!(
            !root.join(path).exists(),
            "probe-owned path remains: {path}"
        );
    }
}

fn assert_retry_succeeds(root: &Path, home: &Path, harness: &Path) {
    let output = topology_command(root, home)
        .env("PERMISSION_TRIAGE_HARNESS_BIN", harness)
        .env(
            "PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS",
            ceiling_ms("topology-auto-executed"),
        )
        .env("FAKE_HARNESS_MODE", "topology-auto-executed")
        .output_serialized()
        .expect("same-root retry exits");
    let verdict = recorded_stdout_verdict(&output.stdout, "retry verdict");
    assert_fake_blocked(&output, &verdict);
}

fn run_with_isolated_topology(binary: &Path, root: &Path, home: &Path, harness: &Path) -> Output {
    topology_command_with_binary(binary, root, home)
        .env(
            "PERMISSION_TRIAGE_HOOK_BIN",
            binary
                .parent()
                .expect("private directory")
                .join("hooks/permission-triage-hook"),
        )
        .env("PERMISSION_TRIAGE_HARNESS_BIN", harness)
        .env(
            "PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS",
            ceiling_ms("topology-auto-executed"),
        )
        .env("FAKE_HARNESS_MODE", "topology-auto-executed")
        .output_serialized()
        .expect("isolated topology binary exits")
}

/// ´test:integration:probe-refuses-unset-relative-and-nonexecutable-harnesses´
#[test]
fn probe_refuses_unset_relative_and_nonexecutable_harnesses() {
    let directory = FixtureDirectory::new("harness-refusals");
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");

    let unset_root = directory.path().join("unset");
    fs::create_dir(&unset_root).expect("unset fixture root is created");
    assert_eq!(run_refusal(&unset_root, &home, None).status.code(), Some(1));

    let relative_root = directory.path().join("relative");
    fs::create_dir(&relative_root).expect("relative fixture root is created");
    let relative = topology_command(&relative_root, &home)
        .env("PERMISSION_TRIAGE_HARNESS_BIN", "fake-harness.sh")
        .output_serialized()
        .expect("relative-path refusal exits");
    assert_eq!(relative.status.code(), Some(1));

    let nonexecuting_root = directory.path().join("nonexecuting");
    let nonexecuting = install_fake_harness(&nonexecuting_root, false);
    assert_eq!(
        run_refusal(&nonexecuting_root, &home, Some(&nonexecuting))
            .status
            .code(),
        Some(1)
    );
}

/// ´test:integration:refusal-unset-permits-same-root-retry´
#[test]
fn refusal_unset_permits_same_root_retry() {
    let directory = FixtureDirectory::new("pre-fixture-refusals");
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let supported_harness_root = directory.path().join("supported-harness");
    let supported_harness = install_fake_harness(&supported_harness_root, true);

    let unset_root = directory.path().join("unset-retry");
    fs::create_dir(&unset_root).expect("unset fixture root is created");
    assert_eq!(run_refusal(&unset_root, &home, None).status.code(), Some(1));
    assert_no_probe_owned_path(&unset_root);
    assert_retry_succeeds(&unset_root, &home, &supported_harness);
}

/// ´test:integration:refusal-relative-permits-same-root-retry´
#[test]
fn refusal_relative_permits_same_root_retry() {
    let directory = FixtureDirectory::new("pre-fixture-refusals");
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let supported_harness_root = directory.path().join("supported-harness");
    let supported_harness = install_fake_harness(&supported_harness_root, true);

    let relative_root = directory.path().join("relative-retry");
    fs::create_dir(&relative_root).expect("relative fixture root is created");
    let relative = topology_command(&relative_root, &home)
        .env("PERMISSION_TRIAGE_HARNESS_BIN", "fake-harness.sh")
        .output_serialized()
        .expect("relative-path refusal exits");
    assert_eq!(relative.status.code(), Some(1));
    assert_no_probe_owned_path(&relative_root);
    assert_retry_succeeds(&relative_root, &home, &supported_harness);
}

/// ´test:integration:refusal-nonexecuting-permits-same-root-retry´
#[test]
fn refusal_nonexecuting_permits_same_root_retry() {
    let directory = FixtureDirectory::new("pre-fixture-refusals");
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let nonexecuting_root = directory.path().join("nonexecuting-retry");
    let nonexecuting = install_fake_harness(&nonexecuting_root, false);
    assert_eq!(
        run_refusal(&nonexecuting_root, &home, Some(&nonexecuting))
            .status
            .code(),
        Some(1)
    );
    assert_no_probe_owned_path(&nonexecuting_root);
    fs::set_permissions(&nonexecuting, fs::Permissions::from_mode(0o700))
        .expect("refused harness becomes executable");
    assert_retry_succeeds(&nonexecuting_root, &home, &nonexecuting);
}

/// ´test:integration:refusal-unsupported-permits-same-root-retry´
#[test]
fn refusal_unsupported_permits_same_root_retry() {
    let directory = FixtureDirectory::new("pre-fixture-refusals");
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let supported_harness_root = directory.path().join("supported-harness");
    let supported_harness = install_fake_harness(&supported_harness_root, true);

    let unsupported_root = directory.path().join("unsupported-retry");
    fs::create_dir(&unsupported_root).expect("unsupported fixture root is created");
    let unsupported = topology_command(&unsupported_root, &home)
        .env("PERMISSION_TRIAGE_HARNESS_BIN", &supported_harness)
        .env(
            "PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS",
            ceiling_ms("wrong-version"),
        )
        .env("FAKE_HARNESS_MODE", "wrong-version")
        .output_serialized()
        .expect("unsupported-version refusal exits");
    assert_eq!(unsupported.status.code(), Some(1));
    assert_no_probe_owned_path(&unsupported_root);
    assert_retry_succeeds(&unsupported_root, &home, &supported_harness);
}

/// ´test:integration:refusal-missing-and-nonexecuting-sibling-permits-same-root-retry´
#[test]
fn refusal_missing_and_nonexecuting_sibling_permits_same_root_retry() {
    let directory = FixtureDirectory::new("pre-fixture-refusals");
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let supported_harness_root = directory.path().join("supported-harness");
    let supported_harness = install_fake_harness(&supported_harness_root, true);

    let isolated_bin = directory.path().join("libexec/superloop");
    fs::create_dir_all(&isolated_bin).expect("isolated binary directory is created");
    let isolated_topology = isolated_bin.join("permission-triage-topology");
    fs::copy(
        env!("CARGO_BIN_EXE_permission-triage-topology"),
        &isolated_topology,
    )
    .expect("topology binary is copied without its sibling");
    fs::set_permissions(&isolated_topology, fs::Permissions::from_mode(0o700))
        .expect("isolated topology binary is executable");
    let missing_sibling_root = directory.path().join("missing-sibling-retry");
    fs::create_dir(&missing_sibling_root).expect("missing-sibling fixture root is created");
    let missing_sibling = run_with_isolated_topology(
        &isolated_topology,
        &missing_sibling_root,
        &home,
        &supported_harness,
    );
    assert_eq!(missing_sibling.status.code(), Some(1));
    assert_no_probe_owned_path(&missing_sibling_root);

    fs::create_dir(isolated_bin.join("hooks")).expect("installed hooks directory");
    let isolated_hook = isolated_bin.join("hooks/permission-triage-hook");
    fs::copy(env!("CARGO_BIN_EXE_permission-triage-hook"), &isolated_hook)
        .expect("sibling hook is copied for retry");
    fs::set_permissions(&isolated_hook, fs::Permissions::from_mode(0o600))
        .expect("isolated sibling hook is non-executable");
    let nonexecuting_sibling = run_with_isolated_topology(
        &isolated_topology,
        &missing_sibling_root,
        &home,
        &supported_harness,
    );
    assert_eq!(nonexecuting_sibling.status.code(), Some(1));
    assert_no_probe_owned_path(&missing_sibling_root);

    fs::set_permissions(&isolated_hook, fs::Permissions::from_mode(0o700))
        .expect("isolated sibling hook is executable");
    let retry = run_with_isolated_topology(
        &isolated_topology,
        &missing_sibling_root,
        &home,
        &supported_harness,
    );
    assert_eq!(retry.status.code(), Some(3));
}

/// ´test:integration:outside-link-collision-is-refused-before-fixture-writes´
#[test]
fn outside_link_collision_is_refused_before_fixture_writes() {
    let directory = FixtureDirectory::new("outside-link-collision");
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME is created");
    let harness = install_fake_harness(&root, true);
    symlink("fake-harness.sh", root.join("outside-link")).expect("foreign outside-link is created");
    let before = snapshot(&root);

    let output = topology_command(&root, &home)
        .env("PERMISSION_TRIAGE_HARNESS_BIN", harness)
        .env(
            "PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS",
            ceiling_ms("topology-auto-executed"),
        )
        .env("FAKE_HARNESS_MODE", "topology-auto-executed")
        .output_serialized()
        .expect("outside-link collision refusal exits");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("probe-owned paths already exist; use a fresh fixture root")
    );
    assert_eq!(snapshot(&root), before);
}

fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>, u32)> {
    fn walk(root: &Path, current: &Path, output: &mut Vec<(PathBuf, Vec<u8>, u32)>) {
        let mut entries = fs::read_dir(current)
            .expect("snapshot directory is readable")
            .map(|entry| entry.expect("snapshot entry is readable"))
            .collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .expect("snapshot path is beneath root")
                .to_path_buf();
            let metadata = fs::symlink_metadata(&path).expect("snapshot metadata is readable");
            if metadata.is_dir() {
                output.push((relative, Vec::new(), metadata.permissions().mode()));
                walk(root, &path, output);
            } else {
                output.push((
                    relative,
                    fs::read(path).expect("snapshot file is readable"),
                    metadata.permissions().mode(),
                ));
            }
        }
    }

    let mut output = Vec::new();
    walk(root, root, &mut output);
    output
}

#[derive(Debug, PartialEq, Eq)]
enum TrackedContents {
    Bytes(Vec<u8>),
    Unreadable(std::io::ErrorKind),
}

fn repository_git_output(root: &Path, args: &[&str], description: &str) -> Output {
    let run = || {
        Command::new("git")
            .arg("--no-optional-locks")
            .args(["-C"])
            .arg(root)
            .args(args)
            .output_serialized()
            .unwrap_or_else(|error| panic!("{description} starts: {error}"))
    };
    let mut output = run();
    if !output.status.success() {
        output = run();
    }
    assert!(output.status.success(), "{description} succeeds");
    output
}

fn git_tracked_paths(root: &Path) -> Vec<PathBuf> {
    let listed = repository_git_output(root, &["ls-files", "-z"], "git ls-files");
    listed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| PathBuf::from(OsString::from_vec(path.to_vec())))
        .collect()
}

fn repository_status(root: &Path) -> Vec<u8> {
    let status = repository_git_output(
        root,
        &["status", "--porcelain", "-uall", "--no-renames"],
        "git status",
    );
    status.stdout
}

/// Ignored paths as Git reports them, so a write beneath an ignored directory is still visible.
///
/// The listing is deliberately not `-uall`: an ignored directory collapses to one entry, which
/// keeps the snapshot bounded even when a repository holds a populated build directory.
fn repository_ignored(root: &Path) -> Vec<u8> {
    let status = repository_git_output(
        root,
        &["status", "--porcelain", "--ignored", "-z"],
        "git status --ignored",
    );
    status.stdout
}

/// The staged entries and every ref, which a working-tree walk cannot see.
///
/// The index is digested by listing it, not by writing a tree: `write-tree` would leave new tree
/// objects in the repository's own object store, which is the opposite of what a confinement
/// snapshot may do. `ls-files -s` reads the same facts — mode, blob identity, stage, path — and
/// writes nothing at all, neither the index nor the object store.
fn repository_index_and_refs(root: &Path) -> (Vec<u8>, Vec<u8>) {
    let staged = repository_git_output(root, &["ls-files", "-s", "-z"], "git ls-files -s");
    let refs = repository_git_output(root, &["for-each-ref"], "git for-each-ref");
    (staged.stdout, refs.stdout)
}

/// Every entry beneath the repository's object store, so a snapshot that writes one is visible.
fn object_store_entries(root: &Path) -> Vec<PathBuf> {
    fn walk(objects: &Path, current: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(current) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("object store entry is readable").path();
            found.push(
                path.strip_prefix(objects)
                    .expect("object path is beneath the object store")
                    .to_path_buf(),
            );
            if path.is_dir() {
                walk(objects, &path, found);
            }
        }
    }

    let objects = root.join(".git").join("objects");
    let mut found = Vec::new();
    walk(&objects, &objects, &mut found);
    found.sort();
    found
}

fn repository_snapshot(
    root: &Path,
    tracked: &[PathBuf],
) -> Vec<(PathBuf, TrackedContents, Option<u32>)> {
    tracked
        .iter()
        .map(|relative| {
            let path = root.join(relative);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    let contents = fs::read(path).map_or_else(
                        |error| TrackedContents::Unreadable(error.kind()),
                        TrackedContents::Bytes,
                    );
                    (
                        relative.clone(),
                        contents,
                        Some(metadata.permissions().mode()),
                    )
                }
                Err(error) => (
                    relative.clone(),
                    TrackedContents::Unreadable(error.kind()),
                    None,
                ),
            }
        })
        .collect()
}

/// ´test:integration:repository-snapshot-is-tracked-only-and-dangling-safe´
#[test]
fn repository_snapshot_is_tracked_only_and_dangling_safe() {
    let directory = FixtureDirectory::new("tracked-snapshot");
    let repository = directory.path().join("repository");
    fs::create_dir(&repository).expect("snapshot repository is created");
    let initialized = Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(&repository)
        .status_serialized()
        .expect("snapshot git init runs");
    assert!(initialized.success());
    fs::write(repository.join("tracked"), b"tracked\n").expect("tracked file is written");
    std::os::unix::fs::symlink("missing-target", repository.join("dangling"))
        .expect("dangling tracked symlink is created");
    fs::write(repository.join("untracked"), vec![b'x'; 1024 * 1024])
        .expect("large untracked file is written");
    let added = Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["add", "tracked", "dangling"])
        .status_serialized()
        .expect("snapshot git add runs");
    assert!(added.success());

    let tracked = git_tracked_paths(&repository);
    let snapshot = repository_snapshot(&repository, &tracked);
    let status = repository_status(&repository);
    assert_eq!(snapshot.len(), 2);
    assert!(snapshot.iter().any(|(path, contents, _mode)| {
        path == Path::new("dangling") && matches!(contents, TrackedContents::Unreadable(_))
    }));
    assert!(!snapshot.iter().any(|(path, _contents, _mode)| {
        path == Path::new("untracked") || path.starts_with(".git")
    }));
    assert!(
        status
            .split(|byte| *byte == b'\n')
            .any(|line| line == b"?? untracked")
    );
}

/// ´test:integration:repository-snapshot-records-ignored-paths-and-index-state´
#[test]
fn repository_snapshot_records_ignored_paths_and_index_state() {
    let directory = FixtureDirectory::new("ignored-and-index-snapshot");
    let repository = directory.path().join("repository");
    fs::create_dir(&repository).expect("snapshot repository is created");
    let initialized = Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(&repository)
        .status_serialized()
        .expect("snapshot git init runs");
    assert!(initialized.success());
    fs::write(repository.join(".gitignore"), b"ignored-*\n").expect("ignore rule is written");
    fs::write(repository.join("tracked"), b"tracked\n").expect("tracked file is written");
    stage_all(&repository);

    let objects_before = object_store_entries(&repository);
    let ignored_before = repository_ignored(&repository);
    let index_before = repository_index_and_refs(&repository);
    assert_eq!(
        objects_before,
        object_store_entries(&repository),
        "taking the snapshot writes nothing into the object store"
    );
    assert_eq!(
        (ignored_before.clone(), index_before.clone()),
        (
            repository_ignored(&repository),
            repository_index_and_refs(&repository)
        ),
        "the snapshot is stable when nothing changed"
    );
    assert_eq!(
        objects_before,
        object_store_entries(&repository),
        "taking the snapshot twice still writes nothing into the object store"
    );

    fs::write(repository.join("ignored-artifact"), b"build output\n")
        .expect("ignored file is written");
    let ignored_after = repository_ignored(&repository);
    let index_after = repository_index_and_refs(&repository);
    assert_ne!(
        ignored_before, ignored_after,
        "an ignored file is a recorded difference"
    );
    assert!(
        ignored_after
            .split(|byte| *byte == 0)
            .any(|entry| entry == b"!! ignored-artifact"),
        "the ignored entry names the planted file"
    );
    assert_eq!(
        index_before, index_after,
        "an ignored file leaves the index and refs alone"
    );

    fs::write(repository.join("staged"), b"staged\n").expect("staged file is written");
    stage_all(&repository);
    assert_ne!(
        index_before,
        repository_index_and_refs(&repository),
        "an index change is a recorded difference"
    );
}

fn stage_all(repository: &Path) {
    let added = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["add", "-A"])
        .status_serialized()
        .expect("snapshot git add runs");
    assert!(added.success());
}

fn assert_probe_confinement(mode: &str, expected_status: i32) {
    // The cache producer performs every snapshot assertion before publishing evidence.
    // Selection and confinement therefore observe the same real, isolated matrix.
    let (output, _verdict) = cached_mode(mode);
    assert_eq!(output.status.code(), Some(expected_status), "mode={mode}");
}

fn run_confined_mode(mode: &str, expected_status: i32) -> CachedProbe {
    let directory = FixtureDirectory::new("filesystem-confinement");
    let environment = directory.path().join("environment");
    let home = environment.join("home");
    let xdg_config = environment.join("xdg-config");
    let xdg_data = environment.join("xdg-data");
    let xdg_cache = environment.join("xdg-cache");
    let temporary = environment.join("tmp");
    let cwd = environment.join("cwd");
    let scratch_roots = [&home, &xdg_config, &xdg_data, &xdg_cache, &temporary, &cwd];
    for root in scratch_roots {
        fs::create_dir_all(root).expect("scratch environment directory is created");
        fs::write(root.join("marker"), b"unchanged\n")
            .expect("scratch environment marker is written");
    }
    let before = scratch_roots
        .iter()
        .map(|root| snapshot(root))
        .collect::<Vec<_>>();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root is canonicalized");
    let repository_paths = git_tracked_paths(&repository);
    let repository_before = repository_snapshot(&repository, &repository_paths);
    let repository_status_before = repository_status(&repository);
    let repository_ignored_before = repository_ignored(&repository);
    let repository_index_before = repository_index_and_refs(&repository);
    let repository_objects_before = object_store_entries(&repository);
    let root = directory.path().join(format!("probe-{mode}"));
    let harness = install_fake_harness(&root, true);
    let verdict_path = root.join("verdict.json");
    let output = topology_command(&root, &home)
        .arg("--verdict")
        .arg(&verdict_path)
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .env("TMPDIR", &temporary)
        .env("PERMISSION_TRIAGE_HARNESS_BIN", harness)
        .env("PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS", ceiling_ms(mode))
        .env("FAKE_HARNESS_MODE", mode)
        .output_serialized()
        .expect("confined topology probe exits");
    assert_eq!(output.status.code(), Some(expected_status), "mode={mode}");
    for (root, expected) in scratch_roots.iter().zip(&before) {
        assert_eq!(
            *expected,
            snapshot(root),
            "root={} mode={mode}",
            root.display()
        );
    }
    assert_eq!(
        repository_before,
        repository_snapshot(&repository, &repository_paths),
        "repository mode={mode}"
    );
    assert_eq!(
        repository_status_before,
        repository_status(&repository),
        "repository status mode={mode}"
    );
    assert_eq!(
        repository_ignored_before,
        repository_ignored(&repository),
        "repository ignored mode={mode}"
    );
    assert_eq!(
        repository_index_before,
        repository_index_and_refs(&repository),
        "repository index and refs mode={mode}"
    );
    assert_eq!(
        repository_objects_before,
        object_store_entries(&repository),
        "repository object store mode={mode}"
    );
    let verdict = serde_json::from_slice(&fs::read(verdict_path).expect("confined verdict"))
        .expect("confined verdict JSON");
    record_observed_walls(&verdict);
    (output, verdict)
}

/// ´test:integration:confinement-topology-auto-refused´
#[test]
fn confinement_topology_auto_refused() {
    assert_probe_confinement("topology-auto-refused", 3);
}

/// ´test:integration:confinement-topology-auto-executed´
#[test]
fn confinement_topology_auto_executed() {
    assert_probe_confinement("topology-auto-executed", 3);
}

/// ´test:integration:confinement-topology-prompt´
#[test]
fn confinement_topology_prompt() {
    assert_probe_confinement("topology-prompt", 3);
}

/// ´test:integration:confinement-topology-changed-command´
#[test]
fn confinement_topology_changed_command() {
    assert_probe_confinement("topology-changed-command", 3);
}

/// ´test:integration:confinement-topology-never-called´
#[test]
fn confinement_topology_never_called() {
    assert_probe_confinement("topology-never-called", 3);
}

/// ´test:integration:confinement-mixed´
#[test]
fn confinement_mixed() {
    assert_probe_confinement("mixed", 3);
}

/// ´test:integration:confinement-topology-ceiling´
#[test]
fn confinement_topology_ceiling() {
    assert_probe_confinement("topology-ceiling", 3);
}

/// ´test:integration:confinement-topology-multiple-denials´
#[test]
fn confinement_topology_multiple_denials() {
    assert_probe_confinement("topology-multiple-denials", 3);
}

/// ´test:integration:confinement-wrong-version´
#[test]
fn confinement_wrong_version() {
    assert_probe_confinement("wrong-version", 1);
}

/// ´test:integration:topology-command-usage-exits-two´
#[test]
fn topology_command_usage_exits_two() {
    let output = Command::new(env!("CARGO_BIN_EXE_permission-triage-topology"))
        .output_serialized()
        .expect("usage invocation exits");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        output.stderr,
        b"usage: permission-triage-topology --fixture-root DIR [--verdict FILE] [--test-roster ROSTER]\n"
    );
}

fn bite_two_good_verdict() -> &'static Value {
    static VERDICT: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    VERDICT.get_or_init(|| {
        let (_directory, output, verdict) =
            run_roster_mode("topology-auto-executed", "implemented");
        assert_eq!(output.status.code(), Some(0), "{}", verdict["reasons"]);
        verdict
    })
}

fn required_rows<'a>(verdict: &'a Value, phase: &str) -> &'a [Value] {
    verdict[phase]
        .as_array()
        .expect("required evidence rows")
        .as_slice()
}

fn required_trial<'a>(verdict: &'a Value, id: &Value) -> &'a Value {
    verdict["trials"]
        .as_array()
        .expect("trials")
        .iter()
        .find(|trial| trial["id"] == *id)
        .expect("correlated trial")
}

fn assert_required_fault(mode: &str, phase: &str, reason: &str) {
    let roster = if phase == "settings_deny_wins" {
        "settings-deny-wins"
    } else {
        phase
    };
    let (_directory, output, verdict) = run_roster_mode(mode, roster);
    assert_eq!(output.status.code(), Some(3), "{mode}");
    assert_eq!(verdict["deployment_blocked"], true, "{mode}");
    let rows = required_rows(&verdict, phase);
    assert!(
        rows.iter().any(|row| {
            row["classification"] == "fail"
                && row["repetitions"].as_array().is_some_and(|ids| {
                    ids.iter()
                        .any(|id| required_trial(&verdict, id)["classification_reason"] == reason)
                })
        }),
        "{mode}: {rows:?}"
    );
}

/// ´test:integration:bite-two-audit-pairs-preserve-harness-control´
#[test]
fn bite_two_audit_pairs_preserve_harness_control() {
    let verdict = bite_two_good_verdict();
    assert_eq!(verdict["schema"], 2);
    let rows = required_rows(verdict, "audit");
    for class in [
        "routine-general",
        "routine-superloop",
        "safe",
        "advanced-read-only",
        "agent-error",
        "suspicious",
    ] {
        for control in ["allow", "deny"] {
            let name = format!("audit-{control}-{class}");
            let row = rows
                .iter()
                .find(|row| row["row"] == name)
                .expect("class/control pair");
            assert_eq!(row["classification"], "pass", "{name}");
            let ids = row["repetitions"].as_array().expect("three repetitions");
            assert_eq!(ids.len(), 3);
            for id in ids {
                let trial = required_trial(verdict, id);
                assert_eq!(trial["hook_stdout"], json!([]));
                assert_eq!(trial["hook_exit_code"], 0);
                assert_eq!(trial["hook_mode"], "audit");
                let events = trial["journal_events"].as_array().expect("verdict journal");
                assert_eq!(events.len(), 1);
                assert_eq!(events[0]["schema"], 2);
                assert_eq!(events[0]["classification"], class);
                assert_eq!(events[0]["emitted_decision"], Value::Null);
                assert_eq!(events[0]["mode"], "audit");
                let baseline = rows
                    .iter()
                    .find(|row| row["row"] == format!("baseline-{control}"))
                    .expect("paired baseline");
                let baseline_id = baseline["repetitions"]
                    .as_array()
                    .expect("baseline repetitions")
                    .first()
                    .expect("baseline trial");
                assert_eq!(
                    trial["classification"],
                    required_trial(verdict, baseline_id)["classification"]
                );
                assert_eq!(
                    events[0]["would_be_decision"],
                    if matches!(class, "agent-error" | "suspicious") {
                        "deny"
                    } else {
                        "allow"
                    }
                );
            }
        }
    }
}

/// ´test:integration:bite-two-bypass-allows-and-denies-have-three-sentinels´
#[test]
fn bite_two_bypass_allows_and_denies_have_three_sentinels() {
    let verdict = bite_two_good_verdict();
    let rows = required_rows(verdict, "bypass");
    assert_eq!(rows.len(), 6);
    for row in rows {
        assert_eq!(row["classification"], "pass");
        let ids = row["repetitions"].as_array().expect("repetitions");
        assert_eq!(ids.len(), 3);
        for id in ids {
            let trial = required_trial(verdict, id);
            assert_eq!(trial["permission_mode"], "bypassPermissions");
            let expected = row["expected_decision"]
                .as_str()
                .expect("expected decision");
            assert_eq!(trial["hook_response"]["decision"], expected);
            assert_eq!(trial["ran"], expected == "allow");
            assert_eq!(trial["prompt"], false);
            assert_eq!(
                trial["journal_events"].as_array().expect("journal").len(),
                1
            );
            assert!(
                trial["argv"]
                    .as_array()
                    .expect("argv")
                    .windows(2)
                    .any(|pair| pair == [json!("--permission-mode"), json!("bypassPermissions")])
            );
        }
    }
}

/// ´test:integration:bite-two-audit-stray-bytes-and-structured-decisions-block´
#[test]
fn bite_two_audit_stray_bytes_and_structured_decisions_block() {
    assert_required_fault("audit-stray-stdout", "audit", "non-silent-audit");
    assert_required_fault("audit-structured-decision", "audit", "non-silent-audit");
}

/// ´test:integration:bite-two-bypass-ignoring-deny-blocks´
#[test]
fn bite_two_bypass_ignoring_deny_blocks() {
    let (_directory, output, verdict) = run_roster_mode("bypass-ignores-deny", "bypass");
    assert_eq!(output.status.code(), Some(3));
    assert_bypass_direction(&verdict, "bypass-agent-error", "deny", true);
}

/// ´test:integration:bite-two-second-gate-refusing-hook-allow-blocks´
#[test]
fn bite_two_second_gate_refusing_hook_allow_blocks() {
    let (_directory, output, verdict) = run_roster_mode("bypass-second-gate", "bypass");
    assert_eq!(output.status.code(), Some(3));
    assert_bypass_direction(&verdict, "bypass-routine-general", "allow", false);
}

fn assert_bypass_direction(verdict: &Value, row_name: &str, decision: &str, ran: bool) {
    let row = required_rows(verdict, "bypass")
        .iter()
        .find(|row| row["row"] == row_name)
        .expect("direction row");
    assert_eq!(row["classification"], "fail");
    let ids = row["repetitions"].as_array().expect("repetitions");
    assert_eq!(ids.len(), 3);
    for id in ids {
        let trial = required_trial(verdict, id);
        assert_eq!(trial["classification_reason"], "outcome-mismatch");
        assert_eq!(trial["ran"], ran);
        assert_eq!(trial["hook_response"]["decision"], decision);
        let bytes = trial["hook_stdout"]
            .as_array()
            .expect("hook bytes")
            .iter()
            .map(|byte| u8::try_from(byte.as_u64().expect("byte")).expect("byte range"))
            .collect::<Vec<_>>();
        let response: Value = serde_json::from_slice(&bytes).expect("hook's own stdout");
        assert_eq!(
            response["hookSpecificOutput"]["permissionDecision"],
            decision
        );
        assert_eq!(
            trial["permission_denials"]
                .as_array()
                .expect("denials")
                .len(),
            usize::from(!ran)
        );
    }
}

/// ´test:integration:bite-two-settings-deny-losing-under-bypass-blocks´
#[test]
fn bite_two_settings_deny_losing_under_bypass_blocks() {
    assert_required_fault(
        "bypass-settings-deny-loses",
        "settings_deny_wins",
        "outcome-mismatch",
    );
}

/// ´test:integration:bite-two-model-instance-and-journal-failures-cannot-execute´
#[test]
fn bite_two_model_instance_and_journal_failures_cannot_execute() {
    assert_required_fault("infra-model-executes", "infrastructure", "outcome-mismatch");
    assert_required_fault(
        "infra-instance-executes",
        "infrastructure",
        "outcome-mismatch",
    );
    assert_required_fault(
        "infra-journal-executes",
        "infrastructure",
        "outcome-mismatch",
    );
}

/// ´test:integration:bite-two-crash-exit-two-and-hook-timeout-cannot-execute´
#[test]
fn bite_two_crash_exit_two_and_hook_timeout_cannot_execute() {
    assert_required_fault("infra-crash-executes", "infrastructure", "outcome-mismatch");
    assert_required_fault(
        "infra-exit-two-executes",
        "infrastructure",
        "outcome-mismatch",
    );
    assert_required_fault(
        "infra-hook-timeout-executes",
        "infrastructure",
        "outcome-mismatch",
    );
}

/// ´test:integration:bite-two-never-called-changed-command-and-tool-failure-block´
#[test]
fn bite_two_never_called_changed_command_and_tool_failure_block() {
    assert_required_fault("bypass-never-called", "bypass", "no-command-proposed");
    assert_required_fault("bypass-changed-command", "bypass", "changed-command");
    assert_required_fault("bypass-tool-failure", "bypass", "tool-failure");
}

/// ´test:integration:bite-two-mixed-repetitions-and-missing-evidence-block´
#[test]
fn bite_two_mixed_repetitions_and_missing_evidence_block() {
    assert_required_fault("bypass-mixed", "bypass", "outcome-mismatch");
    assert_required_fault("bypass-missing-capture", "bypass", "missing-hook-capture");
    assert_required_fault(
        "bypass-missing-model-capture",
        "bypass",
        "missing-model-capture",
    );
    assert_required_fault("bypass-missing-journal", "bypass", "missing-journal-event");
    assert_required_fault("bypass-malformed-result", "bypass", "unparseable-stdout");
}

/// ´test:integration:bite-two-generated-counts-and-censored-latency-survive-failure´
#[test]
fn bite_two_generated_counts_and_censored_latency_survive_failure() {
    let (_output, verdict) = cached_mode("topology-ceiling");
    assert_eq!(verdict["schema"], 2);
    let roster = verdict["roster"].as_array().expect("generated roster");
    assert_eq!(verdict["planned_trials"], roster.len() * 3);
    let trials = verdict["trials"].as_array().expect("trials");
    assert_eq!(
        verdict["friction"]["invocation_wall_ms"]["sample_count"],
        trials.len()
    );
    let censored = trials
        .iter()
        .filter(|trial| trial["timed_out"] == true)
        .count();
    assert!(censored > 0);
    assert_eq!(
        verdict["friction"]["invocation_wall_ms"]["censored_count"],
        censored
    );
    assert!(verdict["friction"]["invocation_wall_ms"]["p95"].is_u64());
}

fn run_roster_mode(mode: &str, roster: &str) -> (FixtureDirectory, Output, Value) {
    run_roster_mode_with_ceiling(mode, roster, "10000")
}

fn run_roster_mode_with_ceiling(
    mode: &str,
    roster: &str,
    configured_ceiling_ms: &str,
) -> (FixtureDirectory, Output, Value) {
    let directory = FixtureDirectory::new(mode);
    let root = directory.probe_root();
    let home = directory.scratch_home();
    fs::create_dir(&home).expect("scratch HOME");
    let harness = install_fake_harness(&root, true);
    let output = topology_command(&root, &home)
        .args(["--test-roster", roster])
        .env("PERMISSION_TRIAGE_HARNESS_BIN", &harness)
        .env(
            "PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS",
            configured_ceiling_ms,
        )
        .env("FAKE_HARNESS_MODE", mode)
        .output_serialized()
        .expect("test roster probe");
    let verdict = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    record_observed_walls(&verdict);
    (directory, output, verdict)
}

/// ´test:integration:fix-deferred-rows-name-bites-without-execution´
#[test]
fn fix_deferred_rows_name_bites_without_execution() {
    let verdict = bite_two_good_verdict();
    for name in ["missing-loop-state-root", "missing-scope", "journal-sync"] {
        let row = required_rows(verdict, "infrastructure")
            .iter()
            .find(|row| row["row"] == name)
            .expect("implemented row");
        assert_eq!(row["classification"], "pass", "{name}");
        assert!(row["deferred_bite"].is_null(), "{name}");
        assert_eq!(row["repetitions"].as_array().expect("repetitions").len(), 3);
    }
    assert_eq!(verdict["failed_rows"], json!([]));
    assert_eq!(verdict["deferred_rows"], json!([]));
    assert_eq!(
        verdict["trials"].as_array().expect("trials").len(),
        (55 + 2 + 44 + 14) * 3
    );
    assert_eq!(verdict["skipped_trials"], 0);
}

/// ´test:integration:fix-implemented-infrastructure-injections-run-three-times´
#[test]
fn fix_implemented_infrastructure_injections_run_three_times() {
    let (_directory, output, verdict) = run_roster_mode("topology-auto-executed", "infrastructure");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for (name, expected_reason_prefix) in [
        (
            "unreadable-registry",
            "infrastructure-failure: caller identity failed:",
        ),
        (
            "unresolved-caller",
            "infrastructure-failure: caller identity failed:",
        ),
        (
            "unsafe-state-root",
            "infrastructure-failure: state routing failed:",
        ),
        (
            "audit-unsafe-state-root",
            "infrastructure-failure: state routing failed:",
        ),
        (
            "unknown-scope",
            "infrastructure-failure: model runner failed: the classifier result violated its schema",
        ),
    ] {
        let row = required_rows(&verdict, "infrastructure")
            .iter()
            .find(|row| row["row"] == name)
            .expect(name);
        assert_eq!(row["classification"], "pass", "{name}");
        assert_eq!(row["expected_reason_prefix"], expected_reason_prefix);
        let repetitions = row["repetitions"].as_array().expect("repetitions");
        assert_eq!(repetitions.len(), 3, "{name}");
        for id in repetitions {
            let trial = required_trial(&verdict, id);
            if name == "audit-unsafe-state-root" {
                assert!(trial["hook_response"].is_null());
            } else {
                assert!(
                    trial["hook_response"]["reason"]
                        .as_str()
                        .is_some_and(|reason| reason.starts_with(expected_reason_prefix)),
                    "{name}"
                );
            }
            if let Some(event) = trial["journal_events"]
                .as_array()
                .and_then(|events| events.first())
            {
                assert!(
                    event["reason"]
                        .as_str()
                        .is_some_and(|reason| reason.starts_with(expected_reason_prefix)),
                    "{name}"
                );
            }
        }
    }
}

/// ´test:integration:fix-failure-keeps-independent-injections-running´
#[test]
fn fix_failure_keeps_independent_injections_running() {
    let (_output, verdict) = cached_mode("infra-model-executes");
    for name in [
        "hook-crash",
        "exit-two",
        "hook-timeout",
        "valid-nested-proof",
    ] {
        let row = required_rows(&verdict, "infrastructure")
            .iter()
            .find(|row| row["row"] == name)
            .expect("independent row");
        assert_eq!(row["classification"], "pass", "{name}");
        assert_eq!(row["repetitions"].as_array().expect("repetitions").len(), 3);
    }
    assert!(
        verdict["failed_rows"]
            .as_array()
            .expect("failed rows")
            .contains(&json!("model-timeout"))
    );
}

/// ´test:integration:fix-implemented-roster-reaches-ready´
#[test]
fn fix_implemented_roster_reaches_ready() {
    let (_directory, output, verdict) = run_roster_mode("topology-auto-executed", "implemented");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(verdict["status"], "ready");
    assert_eq!(verdict["roster_selection"], "test-implemented");
    assert_eq!(verdict["deployment_blocked"], true);
    assert_eq!(verdict["reasons"], json!(["harness: fake"]));
    assert_eq!(verdict["failed_rows"], json!([]));
    assert_eq!(verdict["deferred_rows"], json!([]));
    assert_eq!(verdict["planned_trials"], (55 + 2 + 44 + 14) * 3);
    assert_eq!(verdict["trials"].as_array().expect("trials").len(), 345);
    assert_eq!(verdict["skipped_trials"], 0);
}

/// ´test:integration:fix-baseline-roster-ready-verdict-is-complete´
#[test]
fn fix_baseline_roster_ready_verdict_is_complete() {
    let (_directory, output, verdict) = run_roster_mode("topology-auto-executed", "baseline");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(verdict["status"], "ready");
    assert_eq!(verdict["deployment_blocked"], true);
    assert_eq!(verdict["reasons"], json!(["harness: fake"]));
    assert_eq!(verdict["planned_trials"], 3);
    assert_eq!(verdict["trials"].as_array().expect("trials").len(), 3);
    assert_eq!(verdict["friction"]["hook_wall_ms"]["status"], "no-samples");
}

/// ´test:integration:fix-test-roster-ceiling-floor-retains-selected-rows´
#[test]
fn fix_test_roster_ceiling_floor_retains_selected_rows() {
    let (_directory, output, verdict) =
        run_roster_mode_with_ceiling("topology-auto-executed", "baseline", "1000");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("ceiling_ms=10000"));
    assert_eq!(verdict["status"], "ready");
    for row in required_rows(&verdict, "audit") {
        assert_eq!(row["classification"], "pass");
    }
}

/// ´test:integration:fix-test-roster-refuses-nonfixture-harness´
#[test]
fn fix_test_roster_refuses_nonfixture_harness() {
    let directory = FixtureDirectory::new("test-roster-guard");
    let root = directory.probe_root();
    let harness = install_fake_harness(&root, true);
    write_executable(&harness, b"#!/bin/sh\nprintf '2.1.258\\n'\n", 0o700)
        .expect("different executable");
    let output = topology_command(&root, &directory.scratch_home())
        .args(["--test-roster", "implemented"])
        .env("PERMISSION_TRIAGE_HARNESS_BIN", &harness)
        .env("FAKE_HARNESS_MODE", "topology-auto-executed")
        .output_serialized()
        .expect("guard probe");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("test roster requires"));
    assert!(!root.join("state").exists());
}

/// ´test:integration:fix-baseline-executes-registered-audit-hook´
#[test]
fn fix_baseline_executes_registered_audit_hook() {
    let (directory, _output, verdict) = run_mode("topology-auto-executed");
    let row = required_rows(&verdict, "audit")
        .iter()
        .find(|row| row["row"] == "baseline-allow")
        .expect("baseline");
    for id in row["repetitions"].as_array().expect("repetitions") {
        let trial = required_trial(&verdict, id);
        assert_eq!(trial["audit_hook_mode"], "audit");
        assert_eq!(trial["audit_hook_stdout"], json!([]));
        let log = directory
            .probe_root()
            .join("state/evidence/manual")
            .join(id.as_str().expect("id"))
            .join("audit.jsonl");
        assert!(
            fs::read_to_string(log)
                .expect("retained audit")
                .contains("audit-hook")
        );
    }
}

/// ´test:integration:fix-missing-baseline-registration-blocks´
#[test]
fn fix_missing_baseline_registration_blocks() {
    let (_directory, output, verdict) =
        run_roster_mode("baseline-missing-registration", "baseline");
    assert_eq!(output.status.code(), Some(3));
    let row = &required_rows(&verdict, "audit")[0];
    assert_eq!(row["row"], "baseline-allow");
    assert_eq!(row["classification"], "fail");
    let ids = row["repetitions"].as_array().expect("repetitions");
    assert_eq!(ids.len(), 3);
    for id in ids {
        let trial = required_trial(&verdict, id);
        assert_eq!(trial["classification_reason"], "evidence-mismatch");
        assert_eq!(trial["ran"], true);
        assert_eq!(trial["audit_hook_mode"], Value::Null);
        assert!(
            trial["events"]
                .as_array()
                .expect("lifecycle")
                .iter()
                .all(|event| event["event"] != "PreToolUse")
        );
    }
}

fn assert_registration_fault(
    mode: &str,
    reason: &str,
    observer_present: bool,
    decider_present: bool,
) {
    for (roster, row_name) in [("bypass", "bypass-safe"), ("audit", "audit-allow-safe")] {
        let (_directory, output, verdict) = run_roster_mode(mode, roster);
        assert_eq!(output.status.code(), Some(3), "{mode}:{roster}");
        let row = required_rows(&verdict, roster)
            .iter()
            .find(|row| row["row"] == row_name)
            .expect(row_name);
        assert_eq!(row["classification"], "fail", "{mode}:{roster}");
        for id in row["repetitions"].as_array().expect("repetitions") {
            let trial = required_trial(&verdict, id);
            assert_eq!(trial["classification_reason"], reason, "{mode}:{roster}");
            assert_eq!(
                trial["audit_hook_mode"].is_string(),
                observer_present,
                "{mode}:{roster}"
            );
            assert_eq!(
                trial["hook_exit_code"].is_number(),
                decider_present,
                "{mode}:{roster}"
            );
        }
    }
}

/// ´test:integration:fix-observer-and-decider-registration-twins-are-distinct´
#[test]
fn fix_observer_and_decider_registration_twins_are_distinct() {
    assert_registration_fault(
        "missing-observer-registration",
        "evidence-mismatch",
        false,
        true,
    );
    assert_registration_fault(
        "missing-decider-registration",
        "missing-hook-capture",
        true,
        false,
    );
}

/// ´test:integration:fix-wrong-baseline-registration-blocks´
#[test]
fn fix_wrong_baseline_registration_blocks() {
    assert_required_fault(
        "baseline-wrong-registration",
        "audit",
        "baseline-decision-output",
    );
}

/// ´test:integration:fix-audit-decision-leak-blocks-on-observed-outcome´
#[test]
fn fix_audit_decision_leak_blocks_on_observed_outcome() {
    let (_directory, _output, verdict) = run_roster_mode("audit-decision-leaks", "audit");
    let row = required_rows(&verdict, "audit")
        .iter()
        .find(|row| row["row"] == "audit-allow-agent-error")
        .expect("opposite verdict");
    assert_eq!(row["classification"], "fail");
    for id in row["repetitions"].as_array().expect("repetitions") {
        let trial = required_trial(&verdict, id);
        assert_eq!(trial["hook_response"]["decision"], "deny");
        assert_eq!(trial["ran"], false);
        assert_eq!(trial["classification_reason"], "outcome-mismatch");
    }
}

/// ´test:integration:fix-harness-rejects-argv-payload-mode-mismatch´
#[test]
fn fix_harness_rejects_argv_payload_mode_mismatch() {
    assert_required_fault("payload-mode-mismatch", "bypass", "nonzero-exit");
}

/// ´test:integration:bite-four-sync-failure-is-measured-in-both-modes´
#[test]
fn bite_four_sync_failure_is_measured_in_both_modes() {
    let (directory, output, verdict) = run_roster_mode("topology-auto-executed", "infrastructure");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for name in ["journal-sync"] {
        let row = required_rows(&verdict, "infrastructure")
            .iter()
            .find(|row| row["row"] == name)
            .expect("sync row");
        assert_eq!(row["classification"], "pass", "{name}");
        for id in row["repetitions"].as_array().expect("repetitions") {
            let trial = required_trial(&verdict, id);
            assert!(
                trial["sync_injections"]
                    .as_u64()
                    .is_some_and(|count| count > 0),
                "{name}"
            );
            assert_eq!(trial["ran"], false);
        }
    }
    assert_bite_four_audit_faults(&directory.probe_root());
}

fn assert_bite_four_audit_faults(root: &Path) {
    let input = root.join("state/direct-audit-input.json");
    fs::write(&input, serde_json::to_vec(&json!({"session_id":"topology-session", "cwd":root.join("project"), "permission_mode":"manual", "hook_event_name":"PreToolUse", "tool_name":"Bash", "tool_input":{"command":"triage-sentinel TRIAGE_AUTO_SENTINEL"}, "tool_use_id":"audit-direct"})).expect("input JSON")).expect("input file");
    let direct_driver = |fault: &str| {
        let mut command = Command::new(root.join("bin/real-hook-driver"));
        command
            .env("PERMISSION_TRIAGE_FIXTURE_ROOT", root)
            .env(
                "PERMISSION_TRIAGE_TOPOLOGY_HOOK_BIN",
                env!("CARGO_BIN_EXE_permission-triage-hook"),
            )
            .env("PERMISSION_TRIAGE_CLI", root.join("bin/fake-model-cli"))
            .env(
                "PERMISSION_TRIAGE_FAKE_CAPTURE",
                root.join("state/direct-audit-capture"),
            )
            .env("PERMISSION_TRIAGE_FAKE_RESPONSE", "safe")
            .env("PERMISSION_TRIAGE_FAKE_SCOPE", "loop")
            .env("PERMISSION_TRIAGE_MODE", "audit")
            .env("PERMISSION_TRIAGE_TOPOLOGY_FAULT", fault)
            .env_remove("PERMISSION_TRIAGE_NESTED");
        command
    };
    for fault in ["journal-sync", "missing-loop-state-root", "missing-scope"] {
        let output = direct_driver(fault)
            .output_serialized_with_stdin(fs::File::open(&input).expect("input opens"))
            .expect("audit driver");
        assert_eq!(output.status.code(), Some(0), "{fault}");
        assert!(output.stdout.is_empty(), "{fault}");
        let evidence: Value = serde_json::from_slice(
            &fs::read(root.join("state/hook-invocation.json")).expect("capture"),
        )
        .expect("capture JSON");
        if fault == "missing-scope" {
            assert_eq!(output.stderr, [] as [u8; 0]);
            let events = evidence["journal_events"].as_array().expect("audit events");
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["scope"], "loop");
            assert!(events[0]["emitted_decision"].is_null());
        } else if fault == "missing-loop-state-root" {
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("state routing failed: loop registry entry topology"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        } else {
            assert_eq!(
                output.stderr,
                b"permission-triage: lost audit event: journal publication failed\n"
            );
        }
        if fault == "journal-sync" {
            assert!(
                evidence["sync_injections"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
            );
        }
    }
    let malformed = direct_driver("journal-sync")
        .env("PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS", "not-a-number")
        .output_serialized_with_stdin(fs::File::open(&input).expect("input opens"))
        .expect("malformed ceiling driver");
    assert_eq!(malformed.status.code(), Some(127));
    assert!(
        String::from_utf8_lossy(&malformed.stderr).contains("driver-ceiling"),
        "{}",
        String::from_utf8_lossy(&malformed.stderr)
    );
}

/// ´test:integration:fake-harness-ready-evidence-still-blocks-deployment´
#[test]
fn fake_harness_ready_evidence_still_blocks_deployment() {
    let (output, verdict) = cached_mode("topology-auto-executed");
    assert!(
        verdict["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("harness: fake"))
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(verdict["status"], "blocked");
    assert_eq!(verdict["deployment_blocked"], true);
    assert_eq!(verdict["harness_provenance"]["kind"], "fake");
    assert_eq!(verdict["harness_provenance"]["fake_name_match"], true);
    assert_eq!(verdict["harness_provenance"]["fake_bytes_match"], true);
    assert_eq!(
        verdict["harness_provenance"]["sha256"],
        permission_triage::rubric::sha256_digest(FAKE_HARNESS)
    );
}
