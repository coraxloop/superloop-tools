use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::config::LoopOptions;
use crate::error::{ProvisionError, publication_error};
use crate::keys::parse_key_text;
use crate::runner::{CommandSpec, Runner, failed_command, invoke, require_success};

const COORDINATOR_ENV: &str = "LOOP_KEYGEN_COORDINATOR";
const CLIENT_CONFIG_ENV: &str = "LOOP_KEYGEN_CLIENT_CONFIG";
const SSH_RECORDS_ENV: &str = "LOOP_KEYGEN_SSH_RECORDS";
const ROUTES_ENV: &str = "LOOP_KEYGEN_ROUTES";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SshRoute {
    pub(crate) alias: String,
    pub(crate) address: String,
    pub(crate) port: String,
    pub(crate) host_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SshRecord {
    pub(crate) alias: String,
    pub(crate) user: String,
    pub(crate) identity_file: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoopOutputInput {
    pub(crate) coordinator: String,
    pub(crate) client_config: PathBuf,
    pub(crate) ssh_records: Vec<SshRecord>,
    pub(crate) routes: Vec<SshRoute>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoopPlan {
    paths: [String; 4],
    commands: [CommandSpec; 2],
}

fn loop_paths(options: &LoopOptions) -> Result<[String; 4], ProvisionError> {
    let directory = options
        .directory
        .to_str()
        .ok_or_else(|| ProvisionError::usage("key directory must be UTF-8"))?;
    let master = format!("{directory}/{}_ed25519", options.loop_name);
    let worker = format!("{directory}/{}-codex_ed25519", options.loop_name);
    Ok([
        master.clone(),
        format!("{master}.pub"),
        worker.clone(),
        format!("{worker}.pub"),
    ])
}

pub(crate) fn plan_loop_keygen(
    options: &LoopOptions,
    existing: [bool; 4],
) -> Result<LoopPlan, ProvisionError> {
    let paths = loop_paths(options)?;
    if let Some(path) = paths
        .iter()
        .zip(existing)
        .find_map(|(path, exists)| exists.then_some(path))
    {
        return Err(ProvisionError::refusal(
            "path_exists",
            format!("refusing to overwrite existing key path: {path}"),
        ));
    }
    let commands = [
        CommandSpec::local(
            "generate-loop-master-key",
            vec![
                String::from("ssh-keygen"),
                String::from("-t"),
                String::from("ed25519"),
                String::from("-N"),
                String::new(),
                String::from("-C"),
                format!("{}@workstation", options.loop_name),
                String::from("-f"),
                paths[0].clone(),
            ],
            Vec::new(),
            true,
        ),
        CommandSpec::local(
            "generate-codex-worker-key",
            vec![
                String::from("ssh-keygen"),
                String::from("-t"),
                String::from("ed25519"),
                String::from("-N"),
                String::new(),
                String::from("-C"),
                format!("{}-codex@workstation", options.loop_name),
                String::from("-f"),
                paths[2].clone(),
            ],
            Vec::new(),
            true,
        ),
    ];
    Ok(LoopPlan { paths, commands })
}

fn probe_local_path<R: Runner, W: io::Write>(
    path: &str,
    runner: &mut R,
    output: &mut W,
) -> Result<bool, ProvisionError> {
    for flag in ["-e", "-L"] {
        let command = CommandSpec::local(
            format!("probe-key-path-{flag}-{path}"),
            vec![String::from("test"), flag.to_owned(), path.to_owned()],
            Vec::new(),
            false,
        );
        let result = invoke("account keygen", runner, &command, output)?;
        if result.status == 0 {
            return Ok(true);
        }
        if result.status != 1 {
            return Err(failed_command(&command, &result));
        }
    }
    Ok(false)
}

fn write_verbatim<W: io::Write>(output: &mut W, text: &[u8]) -> Result<(), ProvisionError> {
    output.write_all(text).map_err(publication_error)?;
    if !text.ends_with(b"\n") {
        output.write_all(b"\n").map_err(publication_error)?;
    }
    Ok(())
}

fn required_environment_string<F>(get: &mut F, name: &'static str) -> Result<String, ProvisionError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    get(name)
        .ok_or_else(|| ProvisionError::usage(format!("{name} is required")))?
        .into_string()
        .map_err(|_value| ProvisionError::usage(format!("{name} must be UTF-8")))
}

fn parse_ssh_records(text: &str) -> Result<Vec<SshRecord>, ProvisionError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            let mut fields = line.split('\t');
            let alias = fields.next().unwrap_or_default();
            let user = fields.next();
            let identity_file = fields.next();
            if alias.is_empty()
                || user.is_none_or(str::is_empty)
                || identity_file.is_none_or(str::is_empty)
                || fields.next().is_some()
            {
                return Err(ProvisionError::usage(format!(
                    "{SSH_RECORDS_ENV} line {} must contain exactly alias, user, and identity_file separated by tabs",
                    index + 1
                )));
            }
            Ok(SshRecord {
                alias: alias.to_owned(),
                user: user.unwrap_or_default().to_owned(),
                identity_file: PathBuf::from(identity_file.unwrap_or_default()),
            })
        })
        .collect()
}

pub(crate) fn output_input_from_environment<F>(
    mut get: F,
) -> Result<LoopOutputInput, ProvisionError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let coordinator = required_environment_string(&mut get, COORDINATOR_ENV)?;
    let client_config = PathBuf::from(required_environment_string(&mut get, CLIENT_CONFIG_ENV)?);
    let ssh_records = parse_ssh_records(&required_environment_string(&mut get, SSH_RECORDS_ENV)?)?;
    let routes = parse_routes(&required_environment_string(&mut get, ROUTES_ENV)?)?;
    let input = LoopOutputInput {
        coordinator,
        client_config,
        ssh_records,
        routes,
    };
    validate_output_input(&input)?;
    Ok(input)
}

fn parse_routes(text: &str) -> Result<Vec<SshRoute>, ProvisionError> {
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            let fields: Vec<_> = line.split('\t').collect();
            if !(3..=4).contains(&fields.len()) || fields[..3].contains(&"") {
                return Err(ProvisionError::usage(format!(
                    "{ROUTES_ENV} line {} must contain alias, address, port, and an optional public host key separated by tabs",
                    index + 1
                )));
            }
            let route = SshRoute {
                alias: fields[0].to_owned(),
                address: fields[1].to_owned(),
                port: fields[2].to_owned(),
                host_key: fields.get(3).filter(|key| !key.is_empty()).map(|key| (*key).to_owned()),
            };
            validate_route(&route)?;
            Ok(route)
        })
        .collect()
}

fn route_error(alias: &str, reason: &str) -> ProvisionError {
    ProvisionError::usage(format!("SSH route {alias}: {reason}"))
}

fn validate_route(route: &SshRoute) -> Result<(), ProvisionError> {
    validate_alias_only("route alias", &route.alias)?;
    let address = &route.address;
    let hostname = address.len() <= 253
        && !address
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && address
            .strip_suffix('.')
            .unwrap_or(address)
            .split('.')
            .all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            });
    if address.parse::<IpAddr>().is_err() && !hostname {
        return Err(route_error(
            &route.alias,
            "address must be an IP address or hostname",
        ));
    }
    if !route
        .port
        .parse::<u16>()
        .is_ok_and(|port| port != 0 && port.to_string() == route.port)
    {
        return Err(route_error(
            &route.alias,
            "port must be a canonical decimal from 1 to 65535",
        ));
    }
    if let Some(key) = &route.host_key {
        let fields: Vec<_> = key.split_ascii_whitespace().collect();
        if !(2..=3).contains(&fields.len())
            || key.bytes().any(|byte| byte.is_ascii_control())
            || !matches!(
                fields[0],
                "ssh-ed25519"
                    | "ssh-rsa"
                    | "ecdsa-sha2-nistp256"
                    | "ecdsa-sha2-nistp384"
                    | "ecdsa-sha2-nistp521"
                    | "sk-ssh-ed25519@openssh.com"
                    | "sk-ecdsa-sha2-nistp256@openssh.com"
            )
        {
            return Err(route_error(
                &route.alias,
                "host key must have two or three fields with a known algorithm",
            ));
        }
        crate::keys::validate_key_line(&format!("SSH route {} host key", route.alias), 1, key)?;
    }
    Ok(())
}

fn routes_path(input: &LoopOutputInput) -> PathBuf {
    input.client_config.with_file_name("known_hosts.routes")
}

fn render_known_hosts(input: &LoopOutputInput) -> String {
    let mut rendered = String::new();
    for route in &input.routes {
        if let Some(key) = &route.host_key {
            let mut fields = key.split_ascii_whitespace();
            let host = if route.port == "22" {
                route.address.clone()
            } else {
                format!("[{}]:{}", route.address, route.port)
            };
            writeln!(
                &mut rendered,
                "{host} {} {}",
                fields.next().unwrap_or_default(),
                fields.next().unwrap_or_default()
            )
            .expect("writing to a String cannot fail");
        }
    }
    rendered
}

fn validate_line_value(label: &str, value: &str) -> Result<(), ProvisionError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
    {
        return Err(ProvisionError::usage(format!(
            "{label} must be a non-empty single-line value"
        )));
    }
    Ok(())
}

fn validate_alias_only(label: &str, value: &str) -> Result<(), ProvisionError> {
    let looks_like_endpoint = value.parse::<IpAddr>().is_ok()
        || value.parse::<SocketAddr>().is_ok()
        || value.contains(':');
    if looks_like_endpoint {
        return Err(ProvisionError::refusal(
            "alias_only_addressing",
            format!(
                "SSH record {label} must be an alias, not an address or port-bearing value: {value}"
            ),
        ));
    }
    if value.is_empty()
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProvisionError::refusal(
            "alias_only_addressing",
            format!("SSH record {label} is not a valid alias token: {value}"),
        ));
    }
    Ok(())
}

fn path_text<'a>(label: &str, path: &'a Path) -> Result<&'a str, ProvisionError> {
    let value = path
        .to_str()
        .ok_or_else(|| ProvisionError::usage(format!("{label} must be UTF-8")))?;
    validate_line_value(label, value)?;
    Ok(value)
}

fn validate_output_input(input: &LoopOutputInput) -> Result<(), ProvisionError> {
    validate_line_value("coordinator", &input.coordinator)?;
    path_text("client config", &input.client_config)?;
    let mut aliases = BTreeSet::new();
    for record in &input.ssh_records {
        validate_alias_only("alias", &record.alias)?;
        validate_alias_only("user", &record.user)?;
        path_text("identity file", &record.identity_file)?;
        if !aliases.insert(record.alias.as_str()) {
            return Err(route_error(&record.alias, "duplicate SSH record alias"));
        }
        if input
            .routes
            .iter()
            .filter(|route| route.alias == record.alias)
            .count()
            != 1
        {
            return Err(route_error(&record.alias, "expected exactly one route"));
        }
    }
    for route in &input.routes {
        validate_route(route)?;
        if !aliases.contains(route.alias.as_str()) {
            return Err(route_error(&route.alias, "no matching SSH record"));
        }
    }
    if input.routes.iter().any(|route| route.host_key.is_some()) {
        let path = routes_path(input);
        path_text("routes file", &path)?;
        if path == input.client_config {
            return Err(ProvisionError::usage(
                "client config must differ from known_hosts.routes",
            ));
        }
    }
    Ok(())
}

pub(crate) fn render_request_and_ssh(
    input: &LoopOutputInput,
    loop_name: &str,
    master: &str,
    worker: &str,
) -> Result<String, ProvisionError> {
    validate_output_input(input)?;
    let client_config = path_text("client config", &input.client_config)?;
    let mut rendered = String::new();
    writeln!(
        &mut rendered,
        "--- provisioning request for {} ---\nTo: {}\nloop: {loop_name}\nrequested account: {loop_name}\nloop master public key: {master}\nCodex worker public key: {worker}\n--- end provisioning request ---\nInclude {client_config}",
        input.coordinator, input.coordinator
    )
    .expect("writing to a String cannot fail");
    for record in &input.ssh_records {
        let route = input
            .routes
            .iter()
            .find(|route| route.alias == record.alias)
            .ok_or_else(|| route_error(&record.alias, "missing route"))?;
        let identity_file = path_text("identity file", &record.identity_file)?;
        writeln!(
            &mut rendered,
            "\nHost {}\n    HostName {}\n    Port {}\n    User {}\n    IdentityFile {identity_file}\n    IdentitiesOnly yes",
            record.alias, route.address, route.port, record.user
        )
        .expect("writing to a String cannot fail");
        if route.host_key.is_some() {
            writeln!(
                &mut rendered,
                "    UserKnownHostsFile {}\n    StrictHostKeyChecking yes",
                routes_path(input).display()
            )
            .expect("writing to a String cannot fail");
        } else {
            writeln!(
                &mut rendered,
                "    StrictHostKeyChecking accept-new\n# Note: SSH route {} is unpinned",
                record.alias
            )
            .expect("writing to a String cannot fail");
        }
    }
    Ok(rendered)
}

pub(crate) fn run_loop_keygen<R: Runner, W: io::Write>(
    options: &LoopOptions,
    runner: &mut R,
    output: &mut W,
) -> Result<(), ProvisionError> {
    let output_input = output_input_from_environment(|name| std::env::var_os(name))?;
    run_loop_keygen_with_input(options, &output_input, runner, output)
}

pub(crate) fn run_loop_keygen_with_input<R: Runner, W: io::Write>(
    options: &LoopOptions,
    output_input: &LoopOutputInput,
    runner: &mut R,
    output: &mut W,
) -> Result<(), ProvisionError> {
    validate_output_input(output_input)?;
    let paths = loop_paths(options)?;
    let mut existing = [false; 4];
    for (present, path) in existing.iter_mut().zip(&paths) {
        *present = probe_local_path(path, runner, output)?;
        if *present {
            break;
        }
    }
    let plan = plan_loop_keygen(options, existing)?;
    let known_hosts = render_known_hosts(output_input);
    let known_hosts_path = routes_path(output_input);
    if !known_hosts.is_empty() {
        let path = path_text("routes file", &known_hosts_path)?;
        if probe_local_path(path, runner, output)? {
            return Err(ProvisionError::refusal(
                "path_exists",
                format!("refusing to overwrite existing routes file: {path}"),
            ));
        }
        let command = CommandSpec::local(
            "write-pinned-routes",
            vec![
                "sh".into(),
                "-c".into(),
                "umask 077; set -C; cat > \"$1\"".into(),
                "write-pinned-routes".into(),
                path.into(),
            ],
            known_hosts.into_bytes(),
            true,
        );
        require_success(
            &command,
            invoke("account keygen", runner, &command, output)?,
        )?;
    }
    for command in &plan.commands {
        let result = invoke("account keygen", runner, command, output)?;
        require_success(command, result)?;
    }
    let mut public_keys = Vec::new();
    for (label, path) in [
        ("read-loop-master-public-key", &plan.paths[1]),
        ("read-codex-worker-public-key", &plan.paths[3]),
    ] {
        let command = CommandSpec::local(
            label,
            vec![String::from("cat"), path.clone()],
            Vec::new(),
            false,
        );
        let result = require_success(
            &command,
            invoke("account keygen", runner, &command, output)?,
        )?;
        let text = String::from_utf8(result.stdout).map_err(|_error| {
            ProvisionError::runtime(
                "command_failure",
                format!("public key is not UTF-8: {path}"),
            )
        })?;
        let parsed = parse_key_text(path, &text)?;
        if parsed.len() != 1 {
            return Err(ProvisionError::runtime(
                "command_failure",
                format!("ssh-keygen produced multiple public keys: {path}"),
            ));
        }
        public_keys.push(text);
    }
    write_verbatim(output, public_keys[0].as_bytes())?;
    write_verbatim(output, public_keys[1].as_bytes())?;
    let master = public_keys[0].trim_end();
    let worker = public_keys[1].trim_end();
    let rendered = render_request_and_ssh(output_input, &options.loop_name, master, worker)?;
    output
        .write_all(rendered.as_bytes())
        .map_err(publication_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{Reply, ScriptedRunner};

    fn input(routes: &str) -> Result<LoopOutputInput, ProvisionError> {
        output_input_from_environment(|name| {
            Some(OsString::from(match name {
                COORDINATOR_ENV => "Example Coordinator",
                CLIENT_CONFIG_ENV => "/scratch/ssh_config",
                SSH_RECORDS_ENV => "node-worker\tnew-loop\t/scratch/new-loop-codex_ed25519",
                ROUTES_ENV => routes,
                _ => return None,
            }))
        })
    }

    /// ´test:unit:pinned-route-renders-endpoint-and-strict-companion´
    #[test]
    fn pinned_route_renders_endpoint_and_strict_companion() {
        let input = input("node-worker\t192.0.2.1\t2222\tssh-ed25519 AAAA node")
            .expect("valid pinned route");
        let rendered =
            render_request_and_ssh(&input, "new-loop", "master", "worker").expect("render");
        assert_eq!(
            rendered,
            concat!(
                "--- provisioning request for Example Coordinator ---\n",
                "To: Example Coordinator\nloop: new-loop\nrequested account: new-loop\n",
                "loop master public key: master\nCodex worker public key: worker\n",
                "--- end provisioning request ---\nInclude /scratch/ssh_config\n",
                "\nHost node-worker\n    HostName 192.0.2.1\n    Port 2222\n",
                "    User new-loop\n    IdentityFile /scratch/new-loop-codex_ed25519\n",
                "    IdentitiesOnly yes\n    UserKnownHostsFile /scratch/known_hosts.routes\n",
                "    StrictHostKeyChecking yes\n",
            )
        );
        assert_eq!(
            render_known_hosts(&input),
            "[192.0.2.1]:2222 ssh-ed25519 AAAA\n"
        );
    }

    /// ´test:unit:pinned-default-port-uses-bare-address´
    #[test]
    fn pinned_default_port_uses_bare_address() {
        let input = input("node-worker\t192.0.2.1\t22\tssh-ed25519 AAAA node")
            .expect("valid pinned default-port route");
        assert_eq!(render_known_hosts(&input), "192.0.2.1 ssh-ed25519 AAAA\n");
    }

    /// ´test:unit:unpinned-route-names-alias-and-accepts-new-key´
    #[test]
    fn unpinned_route_names_alias_and_accepts_new_key() {
        for route in [
            "node-worker\tnode.example\t22",
            "node-worker\tnode.example\t22\t",
        ] {
            let input = input(route).expect("unpinned route");
            let rendered =
                render_request_and_ssh(&input, "new-loop", "master", "worker").expect("render");
            assert!(rendered.contains("    HostName node.example\n    Port 22\n"));
            assert!(rendered.contains(
                "    StrictHostKeyChecking accept-new\n# Note: SSH route node-worker is unpinned\n"
            ));
            assert!(!rendered.contains("UserKnownHostsFile"));
            assert_eq!(render_known_hosts(&input), "");
        }
    }

    /// ´test:unit:route-validation-refuses-malformed-address-port-and-key´
    #[test]
    fn route_validation_refuses_malformed_address_port_and_key() {
        for address in [
            "",
            "-node",
            "node example",
            "192.0.2.999",
            "node:2222",
            "[2001:db8::1]",
            "node..example",
            "node\r",
        ] {
            let error = input(&format!("node-worker\t{address}\t2222")).expect_err("bad address");
            assert!(error.diagnostic("keygen").contains("address"));
        }
        for port in ["0", "65536", "-1", "22x", "022", "22 "] {
            let error = input(&format!("node-worker\t192.0.2.1\t{port}"))
                .expect_err("bad routes line port");
            assert!(error.diagnostic("keygen").contains("node-worker"));
            assert!(error.diagnostic("keygen").contains("port"));
        }
        for key in [
            "unknown AAAA",
            "ssh-ed25519",
            "ssh-ed25519 bad!",
            "ssh-ed25519 AAAA two comments",
        ] {
            let error =
                input(&format!("node-worker\t192.0.2.1\t22\t{key}")).expect_err("bad host key");
            assert!(error.diagnostic("keygen").contains("node-worker"));
        }
        input("node-worker\t2001:db8::1\t65535\tssh-ed25519 AAAA").expect("IPv6 route");
    }

    /// ´test:unit:routes-require-exact-alias-correspondence´
    #[test]
    fn routes_require_exact_alias_correspondence() {
        for routes in ["", "node-worker\t192.0.2.1\t22\nnode-worker\t192.0.2.2\t22"] {
            let error = input(routes).expect_err("missing or duplicate route");
            assert!(
                error
                    .diagnostic("keygen")
                    .contains("node-worker: expected exactly one route")
            );
        }
        let error =
            input("node-worker\t192.0.2.1\t22\nextra\t192.0.2.2\t22").expect_err("unmatched route");
        assert!(
            error
                .diagnostic("keygen")
                .contains("extra: no matching SSH record")
        );
        let mut input = input("node-worker\t192.0.2.1\t22").expect("valid route");
        input.ssh_records.push(input.ssh_records[0].clone());
        assert!(
            validate_output_input(&input)
                .expect_err("duplicate record")
                .diagnostic("keygen")
                .contains("node-worker: duplicate SSH record alias")
        );
    }

    /// ´test:unit:invalid-route-runs-no-key-command´
    #[test]
    fn invalid_route_runs_no_key_command() {
        let mut input = input("node-worker\t192.0.2.1\t22").expect("valid route");
        input.routes[0].port = "0".into();
        let mut runner = ScriptedRunner::default();
        let options = LoopOptions {
            loop_name: "new-loop".into(),
            directory: "/scratch".into(),
        };
        run_loop_keygen_with_input(&options, &input, &mut runner, &mut Vec::new())
            .expect_err("refuse before any command");
        assert_eq!(runner.commands, Vec::new());
    }

    /// ´test:unit:pinned-file-is-written-through-runner-before-keys´
    #[test]
    fn pinned_file_is_written_through_runner_before_keys() {
        let input = input("node-worker\t192.0.2.1\t2222\tssh-ed25519 AAAA node")
            .expect("valid pinned route");
        let options = LoopOptions {
            loop_name: "new-loop".into(),
            directory: "/scratch".into(),
        };
        let mut replies = Vec::new();
        for path in loop_paths(&options)
            .expect("paths")
            .into_iter()
            .chain(["/scratch/known_hosts.routes".into()])
        {
            for flag in ["-e", "-L"] {
                replies.push(Reply::status(format!("probe-key-path-{flag}-{path}"), 1));
            }
        }
        replies.extend([
            Reply::success("write-pinned-routes", Vec::new()),
            Reply::success("generate-loop-master-key", Vec::new()),
            Reply::success("generate-codex-worker-key", Vec::new()),
            Reply::success(
                "read-loop-master-public-key",
                b"ssh-ed25519 AAAA master\n".to_vec(),
            ),
            Reply::success(
                "read-codex-worker-public-key",
                b"ssh-ed25519 AAAA worker\n".to_vec(),
            ),
        ]);
        let mut runner = ScriptedRunner::new(replies);
        run_loop_keygen_with_input(&options, &input, &mut runner, &mut Vec::new()).expect("run");
        let write = &runner.commands[10];
        assert_eq!(write.input, b"[192.0.2.1]:2222 ssh-ed25519 AAAA\n");
        assert_eq!(
            write.argv,
            [
                "sh",
                "-c",
                "umask 077; set -C; cat > \"$1\"",
                "write-pinned-routes",
                "/scratch/known_hosts.routes"
            ]
        );
        assert!(write.mutation);
        runner.assert_done();
    }
}
