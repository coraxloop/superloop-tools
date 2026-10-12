use std::io::{self, Write as _};
use std::path::Path;

use superloop_lane::door::final_line;

fn main() {
    superloop_cli_common::version_or_exit("door-ssh", env!("CARGO_PKG_VERSION"), None);
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let socket = Path::new("/home/worker/.local/door/capability.sock");
    let status = match superloop_lane::door::stub_call_stream(
        socket,
        &args,
        io::stdin(),
        io::stdout().lock(),
        io::stderr().lock(),
    ) {
        Ok(reply) => {
            if let Some(line) = final_line(&args, &reply) {
                let _written = writeln!(io::stderr().lock(), "{line}");
            }
            reply["status"]
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .unwrap_or(125)
        }
        Err(error) => {
            let _written = writeln!(io::stderr().lock(), "door-socket: {error}");
            125
        }
    };
    std::process::exit(status);
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::{Cursor, Read as _, Write as _};
    use std::os::unix::net::UnixListener;
    use std::thread;
    use std::time::Duration;

    use serde_json::json;

    use super::final_line;

    /// ´test:unit:door-output-limit-diagnostic-names-budget-and-observation´
    #[test]
    fn door_output_limit_diagnostic_names_budget_and_observation() {
        for state in ["present", "absent", "not-applicable"] {
            let reply = json!({"reason":"door-output-limit-refusal","bound":16_777_216,"output_bytes":16_785_408,"registered":state});
            assert_eq!(
                final_line(&["fixture".into()], &reply),
                Some(format!(
                    "door-output-limit-refusal bound=16777216 output_bytes=16785408 registered={state}"
                ))
            );
        }
    }

    /// ´test:unit:door-ssh-compute-preflight-displays-check-and-wall´
    #[test]
    fn door_ssh_compute_preflight_displays_check_and_wall() {
        for check in [
            "door-compute-words-refusal",
            "door-compute-wrapper-refusal",
            "door-compute-settings-refusal",
            "door-compute-command-refusal",
            "door-compute-locked-refusal",
        ] {
            let fixture = tempfile::tempdir().expect("fixture socket directory");
            let socket = fixture.path().join("capability.sock");
            let listener = UnixListener::bind(&socket).expect("fixture listener");
            let reply = json!({"schema":2,"type":"final","status":125,
                "reason":check,"ref_check":"not-reached","stdin_bytes":0,"stdout_bytes":0,
                "stderr_bytes":0,"queue_state":"no-queue","queue_wall_seconds":null,
                "compute_exit_status":null,"mediation_wall_seconds":0.012_345_678,
                "compute_wall_seconds":0.0});
            let sent = reply.clone();
            let server = thread::spawn(move || {
                let (mut peer, _) = listener.accept().expect("fixture accept");
                peer.set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("fixture deadline");
                let mut length = [0_u8; 4];
                peer.read_exact(&mut length).expect("request length");
                let mut bytes =
                    vec![0_u8; usize::try_from(u32::from_be_bytes(length)).expect("frame size")];
                peer.read_exact(&mut bytes).expect("request frame");
                let request: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("request JSON");
                assert_eq!(request["schema"], 2);
                assert_eq!(request["argv"].as_array().expect("arguments").len(), 2);
                let bytes = serde_json::to_vec(&sent).expect("reply JSON");
                peer.write_all(
                    &u32::try_from(bytes.len())
                        .expect("reply size")
                        .to_be_bytes(),
                )
                .expect("reply length");
                peer.write_all(&bytes).expect("final frame");
            });
            let args = [
                OsString::from("fixture"),
                OsString::from("/opt/fixture/bin/report cargo test"),
            ];
            let received = superloop_lane::door::stub_call_stream(
                &socket,
                &args,
                Cursor::new(Vec::<u8>::new()),
                Vec::new(),
                Vec::new(),
            )
            .expect("real stub transport over fixture socket");
            server.join().expect("fixture service");
            assert_eq!(received, reply);
            assert_eq!(
                final_line(&args, &received),
                Some(format!("{check} check={check} mediation_wall=0.012345678s"))
            );
            let git_args = [
                OsString::from("fixture"),
                OsString::from("git-receive-pack '~/mirrors/R.git'"),
            ];
            assert_eq!(final_line(&git_args, &received), Some(check.to_owned()));
        }
        let args = [
            OsString::from("fixture"),
            OsString::from("/opt/fixture/bin/report cargo test"),
        ];
        assert_eq!(final_line(&args, &json!({"reason":"door-complete"})), None);
        assert_eq!(
            final_line(&args, &json!({"reason":"door-compute-tool-refusal"})),
            Some("door-compute-tool-refusal".to_owned())
        );
    }

    /// ´test:unit:door-ssh-receive-pack-refusal-is-a-bare-reason´
    #[test]
    fn door_ssh_receive_pack_refusal_is_a_bare_reason() {
        let reply = json!({"type":"final","status":125,"reason":"door-changed-ref-refusal",
            "ref_check":"refused"});
        let fixture = tempfile::tempdir().expect("fixture socket directory");
        let socket = fixture.path().join("capability.sock");
        let length = socket.as_os_str().as_encoded_bytes().len();
        assert!(
            length < 108,
            "fixture TMPDIR socket path is {length} bytes; must be shorter than 108 bytes"
        );
        let listener = UnixListener::bind(&socket).expect("fixture listener");
        let final_reply = json!({"schema":2,"type":"final","status":125,
            "reason":"door-changed-ref-refusal","ref_check":"refused","stdin_bytes":0,"stdout_bytes":0,
            "stderr_bytes":0,"queue_state":"no-queue","queue_wall_seconds":null,
            "compute_exit_status":null,"mediation_wall_seconds":0.01,
            "compute_wall_seconds":0.0});
        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("fixture accept");
            peer.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("fixture deadline");
            let mut length = [0_u8; 4];
            peer.read_exact(&mut length).expect("request length");
            let mut bytes =
                vec![0_u8; usize::try_from(u32::from_be_bytes(length)).expect("frame size")];
            peer.read_exact(&mut bytes).expect("request frame");
            let request: serde_json::Value = serde_json::from_slice(&bytes).expect("request JSON");
            assert_eq!(request["schema"], 2);
            assert_eq!(request["argv"].as_array().expect("arguments").len(), 2);
            let bytes = serde_json::to_vec(&final_reply).expect("reply JSON");
            peer.write_all(
                &u32::try_from(bytes.len())
                    .expect("reply size")
                    .to_be_bytes(),
            )
            .expect("reply length");
            peer.write_all(&bytes).expect("final frame");
        });
        let args = [
            OsString::from("fixture"),
            OsString::from("git-receive-pack '~/mirrors/R.git'"),
        ];
        let received = superloop_lane::door::stub_call_stream(
            &socket,
            &args,
            Cursor::new(Vec::<u8>::new()),
            Vec::new(),
            Vec::new(),
        )
        .expect("real stub transport over fixture socket");
        server.join().expect("fixture service");
        assert_eq!(
            final_line(&args, &received),
            Some("door-changed-ref-refusal".to_owned())
        );
        let diagnostic = final_line(&[OsString::from("door-attribution-status")], &reply)
            .expect("diagnostic frame");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&diagnostic).expect("JSON frame"),
            reply
        );
    }
}
