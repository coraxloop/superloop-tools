use execute_command::request::Request;
use serde_json::json;

pub fn request(command: &str, cwd: &str) -> Request {
    Request::from_json(
        &serde_json::to_vec(&json!({
            "schema": 1,
            "binding": {"request_id": "request-1", "context_digest": "context-1"},
            "command": {"representation": "bytes", "bytes": command.as_bytes()},
            "context": {
                "cwd": cwd, "requester": "fixture", "loop_id": "alpha", "lane": null,
                "run": null, "purpose": "parity", "deadline_unix_ms": 0,
                "snapshot": "fixture", "registration": "fixture", "resources": [],
                "authority": "fixture", "checks": [], "rubric": "fixture",
                "mode": "audit", "floor": "audit", "policy": "fixture"
            },
            "implications": {"effects": [], "resources": [], "principals": [],
                "reversibility": "unknown", "scope_uncertainty": "unknown", "evidence": []}
        }))
        .unwrap(),
    )
    .unwrap()
}
