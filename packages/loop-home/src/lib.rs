#![doc = include_str!("../README.md")]

pub mod allocations;
pub mod ancestor;
pub mod anchor;
pub mod app;
pub mod custody;
pub mod door_frame;
mod driver_launch;
pub mod ensure;
pub mod error;
pub mod mail;
pub mod planner;
pub mod registry;
pub mod runner;
pub mod verify;
pub mod workers_settings;

/// Version of the protected boxed driver-entry argument interface.
pub const DRIVER_ENTRY_INTERFACE_VERSION: u32 = 1;

/// Version one fixes the private argument positions, selector and tail boundary.
/// ´claim:loophome:driver-entry-interface-version-pins-private-form´
/// ´test:unit:driver-entry-interface-one-pins-private-form´
#[cfg(test)]
#[test]
fn driver_entry_interface_one_pins_private_form() {
    use std::ffi::OsStr;
    use std::path::PathBuf;

    assert_eq!(
        DRIVER_ENTRY_INTERFACE_VERSION, 1,
        "update the versioned argument contract with the interface version"
    );
    let parse = |words: Vec<&str>| {
        app::parse_invocation(
            OsStr::new("superloop"),
            words,
            None,
            Some(OsStr::new("/fixture/owner")),
        )
    };
    for backend in [
        driver_launch::DriverBackend::Codex,
        driver_launch::DriverBackend::Claude,
    ] {
        let words = vec![
            "driver-launch",
            "alpha",
            "R",
            "--driver-bin",
            "/fixture/driver",
            "--run-dir",
            "/fixture/run",
            "--backend",
            backend.name(),
            "--",
            "--round",
            "work-1",
            "--backend",
            "literal-tail",
            "prompt with spaces",
        ];
        let invocation = parse(words.clone()).expect("version one private form");
        assert_eq!(
            invocation.action,
            app::Action::DriverLaunch {
                name: "alpha".into(),
                run: "R".into(),
                driver_bin: PathBuf::from("/fixture/driver"),
                run_dir: PathBuf::from("/fixture/run"),
                backend,
                arguments: [
                    "--round",
                    "work-1",
                    "--backend",
                    "literal-tail",
                    "prompt with spaces"
                ]
                .map(str::to_owned)
                .to_vec(),
            }
        );
        for end in 1..=10 {
            assert!(parse(words[..end].to_vec()).is_err(), "truncated at {end}");
        }
        for index in [3, 5, 7, 9] {
            let mut changed = words.clone();
            changed[index] = "--unversioned-option";
            assert!(parse(changed).is_err(), "changed boundary at {index}");
        }
        let mut unknown = words.clone();
        unknown[8] = "unversioned-vendor";
        assert!(parse(unknown).is_err());
        let mut unbound = words.clone();
        unbound.drain(7..9);
        assert!(parse(unbound).is_err());
        let mut repeated = words;
        repeated.splice(9..9, ["--backend", backend.name()]);
        assert!(parse(repeated).is_err());
    }
}

pub use app::enter_loop_entry;
pub use custody::{bind_custody_entry, mount_pinned, pin_custody};
pub use ensure::{
    EnsureClass, EnsureCounts, EnsureFailure, RootOwner, StandardRoot, ensure_roots,
    ensure_roots_entry, standard_roots,
};
pub use error::LoopError;
pub use planner::{
    BridgeKind, CommandSpec, Custody, EntryPlan, IoMode, ProvisionPlan, custody_tier, entry_plan,
    provision_plan,
};
pub use registry::{LoopRecord, Registry, load_registry, registry_path, validate_name};
pub use runner::{CommandDescriptors, CommandOutput, ProcessRunner, RunError, Runner};
pub use verify::{VerifyRecord, assemble_verify, cleanup_probe_plan, verify_probe_plan};

#[cfg(test)]
mod tests;
