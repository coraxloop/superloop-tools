//! The installed program's fixed identity and standard stream wiring.

use std::io::Write as _;
use std::process::{Command, Stdio};

use serde_json::json;
use superloop_lane::workspace_node::read_frame;

/// A fictional node cannot become the installed node by a caller-supplied frame.
/// ´test:integration:built-node-entry-refuses-fictional-identity-with-a-typed-frame´
#[test]
fn built_node_entry_refuses_fictional_identity_with_a_typed_frame() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_superloop-lane-node-exec"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("built entry");
    let mut input = child.stdin.take().expect("entry input");
    let body = serde_json::to_vec(
        &json!({"protocol":1,"request_id":"R:1","nonce":"0123456789abcdef",
            "node":"fictional-node-that-is-not-installed","grant":{},
            "placement":{},"envelope":{}}),
    )
    .expect("fictional call JSON");
    let mut frame = u32::try_from(body.len())
        .expect("frame size")
        .to_be_bytes()
        .to_vec();
    frame.extend_from_slice(&body);
    input.write_all(&frame).expect("one call frame write");
    drop(input);
    let refusal = read_frame(child.stdout.as_mut().expect("entry output"))
        .expect("typed refusal on standard output");
    assert_eq!(refusal["schema"], 1);
    assert_eq!(refusal["type"], "refusal");
    assert_eq!(refusal["reason"], "door-workspace-context-differs");
    assert!(!child.wait().expect("entry exit").success());
}
