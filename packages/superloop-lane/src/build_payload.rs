//! Vendor payloads share the image and installation lifecycle.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vendor {
    pub name: &'static str,
    pub program_key: &'static str,
    pub hash_key: &'static str,
    pub version_key: &'static str,
    pub source_key: &'static str,
    pub bin_key: &'static str,
    pub config: &'static str,
    pub charter: &'static str,
}

pub const CODEX: Vendor = Vendor {
    name: "codex",
    program_key: "codex_image_program",
    hash_key: "codex_sha256",
    version_key: "codex_version",
    source_key: "codex_source",
    bin_key: "codex_bin",
    config: "config.toml",
    charter: "AGENTS.md",
};
pub const CLAUDE: Vendor = Vendor {
    name: "claude",
    program_key: "claude_image_program",
    hash_key: "claude_sha256",
    version_key: "claude_version",
    source_key: "claude_source",
    bin_key: "claude_bin",
    config: "settings.json",
    charter: "CLAUDE.md",
};

pub const CLAUDE_IMAGE_PROGRAM: &str = "/usr/libexec/superloop/claude";

/// Select configured payloads, in stable installation order.
#[must_use]
pub fn configured(settings: &Settings) -> Vec<Vendor> {
    [CODEX, CLAUDE]
        .into_iter()
        .filter(|vendor| settings.configures(vendor.name))
        .collect()
}

/// Read a recorded payload program without deriving an absent pin.
///
/// # Errors
/// Refuses an absent or invalid image program.
pub fn image_program(report: &Value, vendor: Vendor) -> Result<String, LaneError> {
    let program = report[vendor.program_key].as_str().ok_or_else(|| {
        LaneError::input("build-report", format!("{} is absent", vendor.program_key))
    })?;
    validate_image_program(program).map_err(|error| LaneError::input("build-report", error.detail))
}

#[derive(Clone, Debug)]
pub struct ProgramInput {
    pub bin: PathBuf,
    pub version: String,
    pub sha256: String,
    pub source: String,
}

/// An installation input bound to the build record for one configured vendor.
#[derive(Clone)]
pub struct InstallPayload {
    pub vendor: Vendor,
    pub bin: PathBuf,
    pub sha256: String,
    pub image_program: String,
    pub companion: Option<(PathBuf, String)>,
}

impl InstallPayload {
    #[must_use]
    pub fn template(&self, loop_root: &Path, image_hash: &str) -> PathBuf {
        loop_root
            .join("runner-templates")
            .join(self.vendor.name)
            .join(image_hash)
    }

    #[must_use]
    pub fn config_source(&self, data: &Path) -> PathBuf {
        data.join(if self.vendor == CODEX {
            "codex-config.toml"
        } else {
            "claude-settings.json"
        })
    }
}

/// Select complete build evidence for the union of configured vendors.
///
/// # Errors
/// Refuses an absent vendor or an incomplete payload, without inventing pins.
pub fn install_payloads(
    report: &Value,
    settings: &Settings,
) -> Result<Vec<InstallPayload>, LaneError> {
    let vendors = configured(settings);
    if vendors.is_empty() {
        return Err(LaneError::input(
            "missing-setting",
            "no vendor is named in backend_argv or vendor_hosts",
        ));
    }
    check_claude_report(report, settings.configures("claude"))?;
    let text = |source: &Value, key: &str| -> Result<String, LaneError> {
        source[key]
            .as_str()
            .filter(|word| !word.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| LaneError::input("build-report", format!("{key} is absent")))
    };
    vendors
        .into_iter()
        .map(|vendor| {
            let program = if vendor == CODEX {
                image_program_from_report(report)?
            } else {
                image_program(report, vendor)?
            };
            let sha256 = text(report, vendor.hash_key)?;
            if !digest(&sha256) {
                return Err(LaneError::input(
                    "build-report",
                    format!("{} is invalid", vendor.hash_key),
                ));
            }
            let companion = if vendor == CODEX {
                let hash = text(report, "codex_host_sha256")?;
                if !digest(&hash) {
                    return Err(LaneError::input(
                        "build-report",
                        "codex_host_sha256 is invalid",
                    ));
                }
                Some((
                    PathBuf::from(text(&report["build_environment"], "codex_host_bin")?),
                    hash,
                ))
            } else {
                None
            };
            Ok(InstallPayload {
                vendor,
                bin: PathBuf::from(text(&report["build_environment"], vendor.bin_key)?),
                sha256,
                image_program: program,
                companion,
            })
        })
        .collect()
}

/// Validate the optional Claude generation group, including its vendor directory.
///
/// # Errors
/// Refuses partial evidence, invalid pins and a template outside its vendor directory.
pub fn check_claude_generation(record: &Value) -> Result<(), LaneError> {
    let keys = [
        "claude_sha256",
        "claude_image_program",
        "claude_template_dir",
    ];
    if keys.iter().all(|key| record.get(*key).is_none()) {
        return Ok(());
    }
    let hash = record["image_digest"]
        .as_str()
        .and_then(|image| image.strip_prefix("sha256:"))
        .filter(|hash| digest(hash))
        .ok_or_else(|| LaneError::input("install-generation", "image digest is invalid"))?;
    let expected = Path::new("runner-templates/claude").join(hash);
    if !record["claude_sha256"].as_str().is_some_and(digest)
        || record["claude_image_program"]
            .as_str()
            .is_none_or(|path| validate_image_program(path).is_err())
        || !record["claude_template_dir"].as_str().is_some_and(|path| {
            validate_image_program(path).is_ok() && Path::new(path).ends_with(&expected)
        })
    {
        return Err(LaneError::input(
            "install-generation",
            "Claude generation is incomplete or names the wrong vendor directory",
        ));
    }
    Ok(())
}

pub(super) fn validate_program(input: &ProgramInput, vendor: Vendor) -> Result<(), LaneError> {
    if input.version.is_empty()
        || !input
            .version
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.')
        || !digest(&input.sha256)
    {
        return Err(LaneError::input(
            "build-input",
            format!("{} version or sha256 pin is invalid", vendor.name),
        ));
    }
    let source = input.source.strip_prefix("https://").ok_or_else(|| {
        LaneError::input(
            "build-input",
            format!("{} source must be an HTTPS artifact address", vendor.name),
        )
    })?;
    let authority = source.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || source
            .bytes()
            .any(|b| !b.is_ascii_graphic() || b == b'?' || b == b'#')
    {
        return Err(LaneError::input(
            "build-input",
            "source must be one HTTPS artifact address without credentials or query",
        ));
    }
    Ok(())
}

pub(super) struct Prepared {
    pub vendors: Vec<Vendor>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub pins: serde_json::Map<String, Value>,
    pub fields: serde_json::Map<String, Value>,
    pub environment: serde_json::Map<String, Value>,
    pub checks: serde_json::Map<String, Value>,
}

impl Prepared {
    pub fn new(
        home: &Path,
        request: &BuildRequest,
        settings: &Settings,
        template: &str,
    ) -> Result<Self, LaneError> {
        let vendors = configured(settings);
        if vendors.is_empty() {
            return Err(LaneError::input(
                "missing-setting",
                "no vendor is named in backend_argv or vendor_hosts",
            ));
        }
        let mut result = Self {
            vendors,
            files: BTreeMap::new(),
            pins: serde_json::Map::new(),
            fields: serde_json::Map::new(),
            environment: serde_json::Map::new(),
            checks: serde_json::Map::new(),
        };
        for vendor in result.vendors.clone() {
            let input = if vendor == CODEX {
                ProgramInput {
                    bin: request.codex_bin.clone(),
                    version: request.codex_version.clone(),
                    sha256: request.codex_sha256.clone(),
                    source: request.codex_source.clone(),
                }
            } else {
                request.claude.clone().ok_or_else(|| LaneError::input("build-input", "configured Claude requires --claude-bin, --claude-version, --claude-sha256 and --claude-source"))?
            };
            validate_program(&input, vendor)?;
            let bytes = source_bytes(&input.bin, vendor.name, MAX_CODEX_BYTES, true)?;
            if vendor == CODEX {
                #[cfg(not(test))]
                standalone_codex(&bytes, &input.bin)?;
            } else {
                native_claude(&bytes)?;
            }
            let measured = hash_bytes(&bytes, &hash_spec(home))?;
            if measured != input.sha256 {
                return Err(LaneError::input(
                    "build-input",
                    format!(
                        "{} program sha256 differs: expected {}, found {measured}",
                        if vendor == CODEX { "Codex" } else { "Claude" },
                        input.sha256
                    ),
                ));
            }
            let program = if vendor == CODEX {
                codex_image_program(template)?
            } else {
                CLAUDE_IMAGE_PROGRAM.into()
            };
            result
                .pins
                .insert(vendor.hash_key.into(), json!(input.sha256));
            result
                .pins
                .insert(vendor.version_key.into(), json!(input.version));
            result
                .pins
                .insert(vendor.source_key.into(), json!(input.source));
            result
                .fields
                .insert(vendor.program_key.into(), json!(program));
            result
                .environment
                .insert(vendor.bin_key.into(), json!(input.bin));
            if vendor == CODEX {
                result.codex_probes(home, request, &bytes)?;
            }
            result.files.insert(vendor.name.into(), bytes);
        }
        Ok(result)
    }

    fn codex_probes(
        &mut self,
        home: &Path,
        request: &BuildRequest,
        bytes: &[u8],
    ) -> Result<(), LaneError> {
        let host = source_bytes(
            &request.codex_host_bin,
            "Codex code-mode host",
            MAX_CODEX_BYTES,
            true,
        )?;
        #[cfg(not(test))]
        standalone_codex(&host, &request.codex_host_bin)?;
        let hash = hash_bytes(&host, &hash_spec(home))?;
        if !digest(&request.codex_host_sha256) || hash != request.codex_host_sha256 {
            return Err(LaneError::input(
                "build-input",
                format!(
                    "Codex code-mode host sha256 differs: expected {}, found {hash}",
                    request.codex_host_sha256
                ),
            ));
        }
        let program = executable_snapshot(bytes)?;
        let companion = executable_snapshot(&host)?;
        let environment = podman_environment(home)?;
        let probe =
            |file: &fs::File, args: Vec<String>, name| -> Result<(String, Value), LaneError> {
                let mut spec = child(
                    Path::new(&format!("/proc/self/fd/{}", file.as_raw_fd())),
                    args,
                    &environment,
                    home,
                    30,
                    name,
                );
                spec.inherited_fd = Some(file.as_raw_fd());
                Ok((checked_output(&spec, None)?, spec.preview()))
            };
        let (version, version_check) = probe(&program, vec!["--version".into()], "codex-version")?;
        let words: Vec<_> = version.split_whitespace().collect();
        if words.len() != 2
            || !["codex", "codex-cli"].contains(&words[0])
            || words[1] != request.codex_version
        {
            return Err(LaneError::input(
                "build-input",
                format!(
                    "Codex program version differs: expected {}, found {}",
                    request.codex_version,
                    version.trim_end().escape_debug()
                ),
            ));
        }
        let (help, help_check) = probe(
            &program,
            vec!["exec".into(), "--help".into()],
            "codex-exec-help",
        )?;
        checked_exec_help(&help)?;
        let (host_help, host_check) = probe(&companion, vec!["--help".into()], "codex-host-help")?;
        if host_help.is_empty() || host_help.len() > MAX_EXEC_HELP_BYTES {
            return Err(LaneError::input(
                "codex-host-help",
                "code-mode host help is absent or too large",
            ));
        }
        self.pins.insert("codex_host_sha256".into(), json!(hash));
        self.fields.insert(
            "codex_host_probe".into(),
            json!({"argv":["--help"],"stdout":host_help,"sha256":hash}),
        );
        self.fields.insert("codex_exec_probe".into(), json!({"argv":["exec","--help"],"stdout":help,"required_options":CODEX_EXEC_OPTIONS,"codex_sha256":request.codex_sha256,"companions":[{"name":"codex-code-mode-host","path":CODEX_HOST_PATH,"sha256":hash}]}));
        self.checks.insert("version_check".into(), version_check);
        self.checks.insert("exec_help_check".into(), help_check);
        self.checks
            .insert("codex_host_help_check".into(), host_check);
        self.environment
            .insert("codex_host_bin".into(), json!(request.codex_host_bin));
        self.files.insert("codex-code-mode-host".into(), host);
        Ok(())
    }

    pub fn seed_keys(&self, settings: &Settings) -> Vec<String> {
        self.vendors
            .iter()
            .filter(|v| !settings.backend_argv.contains_key(v.name))
            .map(|v| format!("backend_argv.{}", v.name))
            .collect()
    }

    pub fn settings(&self, source: &str, image: Option<&str>) -> Result<String, LaneError> {
        let mut parsed: toml::Value = toml::from_str(source)
            .map_err(|e| LaneError::operation("settings-write", e.to_string()))?;
        let table = parsed.as_table_mut().ok_or_else(|| {
            LaneError::operation("settings-write", "settings root is not a table")
        })?;
        let backend = table
            .entry("backend_argv")
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
            .as_table_mut()
            .ok_or_else(|| LaneError::operation("settings-write", "backend_argv is not a table"))?;
        for vendor in &self.vendors {
            let program = image_program(&Value::Object(self.fields.clone()), *vendor)?;
            backend
                .entry(vendor.name)
                .or_insert_with(|| toml::Value::Array(vec![toml::Value::String(program)]));
        }
        if let Some(image) = image {
            table.insert("image_digest".into(), toml::Value::String(image.into()));
        }
        toml::to_string_pretty(&parsed)
            .map_err(|e| LaneError::operation("settings-write", e.to_string()))
    }

    pub fn add_fields(&self, document: &mut Value) {
        if let Some(object) = document.as_object_mut() {
            object.extend(self.pins.clone());
            object.extend(self.fields.clone());
        }
    }
}

fn native_claude(bytes: &[u8]) -> Result<(), LaneError> {
    if bytes.len() < 64 || !bytes.starts_with(b"\x7fELF\x02\x01\x01") {
        return Err(LaneError::input(
            "build-input",
            "Claude must be a native ELF64 little-endian executable, not a script or wrapper",
        ));
    }
    Ok(())
}

pub const CLAUDE_EXEC_OPTIONS: [&str; 10] = [
    "-p",
    "--print",
    "--output-format",
    "--verbose",
    "--permission-mode",
    "--dangerously-skip-permissions",
    "--model",
    "--effort",
    "--resume",
    "--help",
];

fn claude_help(help: &str) -> Result<(), LaneError> {
    if help.len() > 65_536
        || CLAUDE_EXEC_OPTIONS
            .iter()
            .any(|option| !exec_help_has_option(help, option))
        || !help.contains("stream-json")
        || !help.contains("bypassPermissions")
        || !help.contains("acceptEdits")
        || !help.contains("plan")
    {
        return Err(LaneError::input(
            "claude-exec-help",
            "Claude help exceeds its bound or lacks a required print option or choice",
        ));
    }
    Ok(())
}

pub(super) fn claude_probe_spec(
    request: &BuildRequest,
    home: &Path,
    image: &str,
) -> Result<ChildSpec, LaneError> {
    Ok(child(
        &request.podman_bin,
        vec![
            "run".into(),
            "--rm".into(),
            "--network=none".into(),
            "--pull=never".into(),
            "--read-only".into(),
            "--tmpfs=/tmp:rw,noexec,nosuid".into(),
            "--entrypoint=/usr/bin/python3".into(),
            image.into(),
            "-c".into(),
            include_str!("claude_image_probe.py").into(),
        ],
        &podman_environment(home)?,
        home,
        30,
        "claude-image-probe",
    ))
}

pub(super) fn probe_claude(
    request: &BuildRequest,
    home: &Path,
    image: &str,
) -> Result<(Value, Value), LaneError> {
    let input = request
        .claude
        .as_ref()
        .ok_or_else(|| LaneError::input("build-input", "Claude input is absent"))?;
    let output = checked_output(&claude_probe_spec(request, home, image)?, None)?;
    let measured: Value = serde_json::from_str(&output)
        .map_err(|e| LaneError::input("claude-image-probe", e.to_string()))?;
    if measured["sha256"] != input.sha256
        || measured["version"].as_str().map(str::trim)
            != Some(format!("{} (Claude Code)", input.version).as_str())
    {
        return Err(LaneError::input(
            "claude-image-probe",
            "image Claude hash or version differs from its input",
        ));
    }
    let help = measured["help"]
        .as_str()
        .ok_or_else(|| LaneError::input("claude-exec-help", "image help is absent"))?;
    claude_help(help)?;
    let runtime = json!({"image_digest":image,"interpreter":measured["interpreter"],"libraries":measured["libraries"]});
    check_runtime(&runtime, image)?;
    Ok((
        json!({"argv":["--help"],"stdout":help,"required_options":CLAUDE_EXEC_OPTIONS,"claude_sha256":input.sha256,"image_digest":image,"companions":[]}),
        runtime,
    ))
}

fn check_runtime(runtime: &Value, image: &str) -> Result<(), LaneError> {
    let entry = |value: &Value| {
        value.as_object().is_some_and(|map| map.len() == 2)
            && value["path"]
                .as_str()
                .is_some_and(|path| validate_image_program(path).is_ok())
            && value["sha256"].as_str().is_some_and(digest)
    };
    if runtime.as_object().is_none_or(|map| map.len() != 3)
        || runtime["image_digest"] != image
        || !entry(&runtime["interpreter"])
        || runtime["libraries"]
            .as_array()
            .is_none_or(|rows| rows.is_empty() || !rows.iter().all(entry))
    {
        return Err(LaneError::input(
            "claude-runtime",
            "Claude image runtime evidence is absent or invalid",
        ));
    }
    Ok(())
}

/// Validate optional Claude evidence as one complete payload; never supply missing pins.
///
/// # Errors
/// Refuses partial evidence, changed image bindings, or unsupported CLI options.
pub fn check_claude_report(report: &Value, required: bool) -> Result<(), LaneError> {
    let keys = [
        "claude_version",
        "claude_sha256",
        "claude_source",
        "claude_image_program",
        "claude_exec_probe",
        "claude_runtime",
    ];
    if !required
        && keys.iter().all(|key| report.get(*key).is_none())
        && report["build_environment"].get("claude_bin").is_none()
    {
        return Ok(());
    }
    let string = |key| {
        report[key]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| LaneError::input("build-report", format!("{key} is absent")))
    };
    let input = ProgramInput {
        bin: PathBuf::from(
            report["build_environment"]["claude_bin"]
                .as_str()
                .ok_or_else(|| {
                    LaneError::input("build-report", "build_environment.claude_bin is absent")
                })?,
        ),
        version: string("claude_version")?.into(),
        sha256: string("claude_sha256")?.into(),
        source: string("claude_source")?.into(),
    };
    validate_program(&input, CLAUDE)?;
    if !input.bin.is_absolute() {
        return Err(LaneError::input(
            "build-report",
            "Claude source path is not absolute",
        ));
    }
    if image_program(report, CLAUDE)? != CLAUDE_IMAGE_PROGRAM {
        return Err(LaneError::input(
            "build-report",
            "claude_image_program differs from the image probe program",
        ));
    }
    let image = string("image_digest")?;
    check_runtime(&report["claude_runtime"], image)?;
    let probe = &report["claude_exec_probe"];
    if probe.as_object().is_none_or(|map| map.len() != 6)
        || probe["argv"] != json!(["--help"])
        || probe["required_options"] != json!(CLAUDE_EXEC_OPTIONS)
        || probe["claude_sha256"] != input.sha256
        || probe["image_digest"] != image
        || probe["companions"] != json!([])
    {
        return Err(LaneError::input(
            "claude-exec-help",
            "Claude exec probe differs from its image or program",
        ));
    }
    claude_help(
        probe["stdout"]
            .as_str()
            .ok_or_else(|| LaneError::input("claude-exec-help", "Claude exec help is absent"))?,
    )
}
