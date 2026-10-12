use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::error::LaneError;

const CAP: u64 = 64 * 1024 * 1024;

fn failure(detail: impl Into<String>) -> LaneError {
    LaneError::input("requests-helper-refusal", detail)
}

#[derive(Clone)]
pub(super) struct Client {
    pub(super) helper: PathBuf,
    pub(super) registry: PathBuf,
}

impl Client {
    pub(super) fn configured() -> Result<Self, LaneError> {
        #[cfg(test)]
        if let Some(client) = TEST_CLIENT.with(|value| value.borrow().clone()) {
            return Ok(client);
        }
        let helper = std::env::var_os("SUPERLOOP_LANE_REQUESTS_HELPER")
            .map(PathBuf::from)
            .or_else(|| option_env!("SUPERLOOP_LANE_REQUESTS_HELPER").map(PathBuf::from))
            .ok_or_else(|| failure("SUPERLOOP_LANE_REQUESTS_HELPER is unset"))?;
        let registry = std::env::var_os("PERMISSION_TRIAGE_LOOP_REGISTRY")
            .map(PathBuf::from)
            .ok_or_else(|| failure("PERMISSION_TRIAGE_LOOP_REGISTRY is unset"))?;
        Self::paths(helper, registry)
    }

    pub(super) fn for_registry(registry: &std::path::Path) -> Result<Self, LaneError> {
        #[cfg(test)]
        let helper = super::store::test_helper::binary().to_path_buf();
        #[cfg(not(test))]
        let helper = std::env::var_os("SUPERLOOP_LANE_REQUESTS_HELPER")
            .map(PathBuf::from)
            .or_else(|| option_env!("SUPERLOOP_LANE_REQUESTS_HELPER").map(PathBuf::from))
            .ok_or_else(|| failure("SUPERLOOP_LANE_REQUESTS_HELPER is unset"))?;
        Self::paths(helper, registry.to_path_buf())
    }

    fn paths(helper: PathBuf, registry: PathBuf) -> Result<Self, LaneError> {
        if !helper.is_absolute() || !registry.is_absolute() {
            return Err(failure("helper and registry paths must be absolute"));
        }
        Ok(Self { helper, registry })
    }

    pub(super) fn decode(value: &Value, loop_name: &str) -> Result<Self, LaneError> {
        if value.as_object().is_none_or(|object| object.len() != 4)
            || value["schema"] != 1
            || value["loop"] != loop_name
        {
            return Err(failure("channel binding fields differ"));
        }
        Self::paths(
            PathBuf::from(
                value["helper"]
                    .as_str()
                    .ok_or_else(|| failure("helper path absent"))?,
            ),
            PathBuf::from(
                value["registry"]
                    .as_str()
                    .ok_or_else(|| failure("registry path absent"))?,
            ),
        )
    }

    pub(super) fn value(&self, loop_name: &str) -> Value {
        json!({"schema":1,"loop":loop_name,"helper":self.helper,"registry":self.registry})
    }

    pub(super) fn call(
        &self,
        phase: &str,
        action: &str,
        loop_name: &str,
        input: Option<&Value>,
    ) -> Result<Value, LaneError> {
        let mut command = Command::new(&self.helper);
        command.arg(phase);
        if phase != "--owner-read" {
            command.arg(action);
        }
        if phase != "--registry-validate" {
            command.args(["--loop", loop_name]);
        }
        command
            .env("PERMISSION_TRIAGE_LOOP_REGISTRY", &self.registry)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let bytes = input
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| failure(error.to_string()))?
            .unwrap_or_default();
        if bytes.len() as u64 > CAP {
            return Err(failure("owner input exceeds cap"));
        }
        let mut child = command
            .spawn()
            .map_err(|error| failure(format!("{}: {error}", self.helper.display())))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| failure("helper stdin absent"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| failure("helper stderr absent"))?;
        let writer = std::thread::spawn(move || stdin.write_all(&bytes));
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.take(65_537).read_to_end(&mut bytes).map(|_| bytes)
        });
        let mut output = Vec::new();
        let read = child
            .stdout
            .take()
            .ok_or_else(|| failure("helper stdout absent"))?
            .take(CAP + 1)
            .read_to_end(&mut output);
        if read.is_err() || output.len() as u64 > CAP {
            let _killed = child.kill();
        }
        let status = child.wait().map_err(|error| failure(error.to_string()));
        let written = writer
            .join()
            .map_err(|_| failure("helper input thread failed"))?;
        let diagnostic = errors
            .join()
            .map_err(|_| failure("helper error thread failed"))?
            .map_err(|error| failure(error.to_string()))?;
        read.map_err(|error| failure(error.to_string()))?;
        if !status?.success() {
            return Err(failure(String::from_utf8_lossy(&diagnostic).into_owned()));
        }
        written.map_err(|error| failure(error.to_string()))?;
        if output.len() as u64 > CAP || diagnostic.len() > 65_536 {
            return Err(failure("helper output exceeds cap"));
        }
        serde_json::from_slice(&output)
            .map_err(|error| failure(format!("invalid helper reply: {error}")))
    }
}

#[cfg(test)]
thread_local! { static TEST_CLIENT: std::cell::RefCell<Option<Client>> = const { std::cell::RefCell::new(None) }; }

#[cfg(test)]
pub(super) fn with_test_client<T>(
    helper: &std::path::Path,
    registry: &std::path::Path,
    call: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Client>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_CLIENT.with(|value| *value.borrow_mut() = self.0.take());
        }
    }
    let previous = TEST_CLIENT.with(|value| {
        value.replace(Some(Client {
            helper: helper.to_path_buf(),
            registry: registry.to_path_buf(),
        }))
    });
    let _restore = Restore(previous);
    call()
}
