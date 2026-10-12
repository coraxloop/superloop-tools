//! Two serve generations in one process, each entered from its own thread.
//!
//! A signal mask is per-thread, so "the watched signals are blocked while
//! serving" is a claim about every thread that enters `serve`, not about the
//! process. Only a process that serves twice from two different threads can
//! check it, and what a process has already installed is global state, so this
//! scenario owns a test binary rather than sharing one: in any other binary the
//! generation under test would not be the second generation.
//!
//! Delivering a real signal is the subprocess tests' job. A process-directed
//! signal goes to any thread that does not block it, the test harness runs a
//! test body on a thread it spawns rather than on the process's main thread,
//! and a test cannot set the mask of a thread it did not create — so an
//! in-process delivery would end this binary whether or not serving blocks
//! correctly. The mask each serving thread carries is the claim, and it is
//! decidable without delivering anything.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`every_serve_generation_blocks_the_watched_signals_on_its_own_thread`] |  | — |

use std::fs;
mod support;
use std::path::{Path, PathBuf};
use std::thread;

use lane_gateway::{Gateway, GatewayError, ServeConfig};
use nix::sys::signal::{SigSet, Signal};

/// Signals every serving thread must have blocked, whichever thread it is.
const WATCHED: [Signal; 3] = [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP];

/// Serving twice from two different threads leaves both threads with the
/// watched signals blocked, so a second generation cannot take one with its
/// default disposition and end a process whose heartbeat still says `running`.
///
/// ´test:integration:every-serve-generation-blocks-the-watched-signals-on-its-own-thread´
#[test]
fn every_serve_generation_blocks_the_watched_signals_on_its_own_thread() {
    let directory = TestDirectory::new();
    let first = serve_generation(&directory.path().join("first"));
    // Strictly sequential: the second generation is entered only after the
    // first has stopped, which is what a replacement serve in one process does
    // and what makes the second generation's mask the installation's own work
    // rather than an inheritance from a thread that is still serving.
    let second = serve_generation(&directory.path().join("second"));

    for (generation, mask) in [("first", first), ("second", second)] {
        for signal in WATCHED {
            assert!(
                mask.contains(signal),
                "{generation} generation served with {signal} unblocked"
            );
        }
    }
}

/// Serve one generation on a fresh thread and report that thread's final mask.
///
/// The generation stops on its own shutdown flag, written before it starts, so
/// the scenario needs no signal and no waiting: the loop checks the flag at the
/// top of its first cycle and returns.
fn serve_generation(state: &Path) -> SigSet {
    fs::create_dir(state).expect("generation state root is created");
    let (helper, registry, loop_name) = support::settings(state);
    let gateway = Gateway::new(state.to_path_buf()).with_request_channel(
        lane_gateway::RequestChannel::new(helper, registry, loop_name).expect("journal binding"),
    );
    let config = ServeConfig::for_gateway(&gateway)
        .with_runner_prefix(vec!["/bin/false".to_owned()])
        .with_heartbeat_interval_millis(10);
    fs::write(config.shutdown_file(), b"stop\n").expect("generation shutdown flag is written");
    let served = thread::spawn(move || -> (Result<(), GatewayError>, SigSet) {
        let outcome = gateway.serve(&config);
        (
            outcome,
            SigSet::thread_get_mask().expect("serving thread mask is readable"),
        )
    });
    let (outcome, mask) = served.join().expect("generation thread joins");
    outcome.expect("generation stops cleanly on its shutdown flag");

    let heartbeat = fs::read_to_string(state.join("serve-heartbeat.json"))
        .expect("generation heartbeat is readable");
    let heartbeat: serde_json::Value =
        serde_json::from_str(&heartbeat).expect("generation heartbeat is strict JSON");
    assert_eq!(heartbeat["process_state"], "stopped");
    assert_eq!(heartbeat["stop_reason"], "shutdown_flag");
    mask
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lane-gateway-serve-generations-{}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("generations test directory is created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.path));
    }
}
