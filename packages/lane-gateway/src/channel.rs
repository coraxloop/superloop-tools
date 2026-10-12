//! Exact-path transport to the calling loop's private request journal.

use crate::GatewayError;
use request_core::{Collection, Request};
use serde_json::{Value, json};
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const CAP: u64 = 64 * 1024 * 1024;
fn failure(detail: impl Into<String>) -> GatewayError {
    GatewayError::RequestChannel(detail.into())
}

/// An explicit executable and registry binding, never an estate-wide journal.
#[derive(Clone, Debug)]
pub struct RequestChannel {
    helper: PathBuf,
    registry: PathBuf,
    loop_name: String,
}

impl RequestChannel {
    /// Bind the helper and registry by absolute path.
    ///
    /// # Errors
    /// Refuses a relative path or an empty loop name before executing anything.
    pub fn new(
        helper: PathBuf,
        registry: PathBuf,
        loop_name: String,
    ) -> Result<Self, GatewayError> {
        if !helper.is_absolute() || !registry.is_absolute() || loop_name.is_empty() {
            return Err(failure(
                "absolute helper, absolute registry and loop name required",
            ));
        }
        Ok(Self {
            helper,
            registry,
            loop_name,
        })
    }

    pub(crate) fn configured() -> Result<Self, GatewayError> {
        let helper = std::env::var_os("SUPERLOOP_GATEWAY_REQUESTS_HELPER")
            .or_else(|| option_env!("SUPERLOOP_GATEWAY_REQUESTS_HELPER").map(Into::into))
            .ok_or_else(|| failure("SUPERLOOP_GATEWAY_REQUESTS_HELPER is unset"))?;
        let registry = std::env::var_os("PERMISSION_TRIAGE_LOOP_REGISTRY")
            .ok_or_else(|| failure("PERMISSION_TRIAGE_LOOP_REGISTRY is unset"))?;
        let loop_name = std::env::var("SUPERLOOP_GATEWAY_LOOP")
            .map_err(|_| failure("SUPERLOOP_GATEWAY_LOOP is unset"))?;
        Self::new(helper.into(), registry.into(), loop_name)
    }

    pub(crate) fn loop_name(&self) -> &str {
        &self.loop_name
    }

    pub(crate) fn read(&self) -> Result<Collection, GatewayError> {
        serde_json::from_value(self.call("--owner-read", "", &self.loop_name, None)?)
            .map_err(|error| failure(error.to_string()))
    }

    pub(crate) fn change(
        &self,
        action: &str,
        records: &[Request],
        document: Option<Value>,
    ) -> Result<Value, GatewayError> {
        let mut input = json!({"schema":1,"records":records,"document":null,"id":null,
            "pending":false,"now_ns":request_core::now_ns().map_err(|error| failure(error.to_string()))?,
            "expected":null,"publication":null});
        input["document"] = document.unwrap_or(Value::Null);
        let preview = self.call("--owner-preview", action, &self.loop_name, Some(&input))?;
        input["expected"] = preview["before"].clone();
        self.call("--owner-commit", action, &self.loop_name, Some(&input))
    }
    pub(super) fn call(
        &self,
        phase: &str,
        action: &str,
        loop_name: &str,
        input: Option<&Value>,
    ) -> Result<Value, GatewayError> {
        let mut command = Command::new(&self.helper);
        command.arg(phase);
        if phase != "--owner-read" {
            command.arg(action);
        }
        command
            .args(["--loop", loop_name])
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
