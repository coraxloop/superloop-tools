use super::*;
use crate::launch::control::{Operation, actions::Outcome};
fn exchange(
    f: &Fixture,
    client: &mut Opened,
    operation: Operation,
    change: impl FnOnce(&mut serde_json::Value) + Send,
) -> Result<Outcome> {
    std::thread::scope(|scope| {
        let server=scope.spawn(|| {
            let (mut stream,_)=f.listener.accept().unwrap();stream.set_nonblocking(true).unwrap();
            let bytes=super::super::super::read_request(&mut stream,deadline()).unwrap();
            let request:super::super::super::Request=serde_json::from_slice(&bytes).unwrap();
            let outcome=match request.operation {
                Operation::Inventory=>serde_json::json!({"inventory":{"inventory_sha256":"d".repeat(64)}}),
                Operation::Release{inventory_sha256}=>serde_json::json!({"released":{"inventory_sha256":inventory_sha256}}),
                _=>panic!("wrong action"),
            };
            let mut value=serde_json::json!({"schema":2,"case":request.case,"keeper_pid":request.keeper_pid,"keeper_birth":request.keeper_birth,"invocation":request.invocation,"nonce":request.nonce,"outcome":outcome});change(&mut value);
            let mut bytes=serde_json::to_vec(&value).unwrap();bytes.push(b'\n');super::super::super::write_record(&mut stream,&bytes,deadline()).unwrap();
        });
        let result = client.action(operation, deadline());
        server.join().unwrap();
        result
    })
}
/// ´test:unit:protected-administrative-client-binds-actions-and-reconnects´
#[test]
fn protected_administrative_client_binds_actions_and_reconnects() {
    let _guard = crate::launch::test_support::case_guard();
    let f = Fixture::new();
    let mut client = f.open().unwrap();
    let mut nonces = Vec::new();
    assert_eq!(
        exchange(&f, &mut client, Operation::Inventory, |v| nonces
            .push(v["nonce"].clone())),
        Ok(Outcome::Inventory {
            inventory_sha256: "d".repeat(64)
        })
    );
    client.reconnect(deadline()).unwrap();
    assert_eq!(
        exchange(
            &f,
            &mut client,
            Operation::Release {
                inventory_sha256: "d".repeat(64)
            },
            |v| nonces.push(v["nonce"].clone())
        ),
        Ok(Outcome::Released {
            inventory_sha256: "d".repeat(64)
        })
    );
    assert_ne!(nonces[0], nonces[1]);
    client.reconnect(deadline()).unwrap();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (mut stream, _) = f.listener.accept().unwrap();
            stream.set_nonblocking(true).unwrap();
            let bytes = super::super::super::read_request(&mut stream, deadline()).unwrap();
            let request: super::super::super::Request = serde_json::from_slice(&bytes).unwrap();
            assert!(matches!(request.operation, Operation::Observed));
            assert_eq!(request.schema, 2);
            assert_eq!(request.invocation, f.value["invocation"]);
        });
        client.observed(deadline()).unwrap();
        server.join().unwrap();
    });
}
/// ´test:unit:protected-administrative-client-refuses-reply-drift´
#[test]
fn protected_administrative_client_refuses_reply_drift() {
    let _guard = crate::launch::test_support::case_guard();
    for (field, value, class) in [
        ("schema", serde_json::json!(1), "client-action-binding"),
        (
            "case",
            serde_json::json!("foreign"),
            "client-action-binding",
        ),
        ("keeper_pid", serde_json::json!(1), "client-action-binding"),
        (
            "keeper_birth",
            serde_json::json!(1),
            "client-action-binding",
        ),
        (
            "invocation",
            serde_json::json!("f".repeat(32)),
            "client-action-binding",
        ),
        (
            "nonce",
            serde_json::json!("f".repeat(32)),
            "client-action-binding",
        ),
        ("extra", serde_json::json!(true), "client-action-record"),
        (
            "outcome",
            serde_json::json!({"released":{"inventory_sha256":"d".repeat(64)}}),
            "client-action-outcome",
        ),
        (
            "outcome",
            serde_json::json!({"inventory":{"inventory_sha256":"D".repeat(64)}}),
            "client-action-digest",
        ),
    ] {
        let f = Fixture::new();
        let mut client = f.open().unwrap();
        assert_eq!(
            exchange(&f, &mut client, Operation::Inventory, |v| v[field] = value),
            Err(class),
            "{field}"
        );
    }
    let f = Fixture::new();
    let mut client = f.open().unwrap();
    assert_eq!(
        exchange(
            &f,
            &mut client,
            Operation::Release {
                inventory_sha256: "e".repeat(64)
            },
            |v| v["outcome"]["released"]["inventory_sha256"] = "d".repeat(64).into()
        ),
        Err("client-action-digest")
    );
    assert_eq!(
        client.action(Operation::Observed, deadline()),
        Err("client-operation")
    );
    f.write();
    assert_eq!(client.reconnect(deadline()), Err("client-record-binding"));
    let f = Fixture::new();
    let mut client = f.open().unwrap();
    assert_eq!(
        exchange(&f, &mut client, Operation::Inventory, |_| f.write()),
        Err("client-record-binding")
    );
    let f = Fixture::new();
    let mut client = f.open().unwrap();
    f.write();
    assert_eq!(client.observed(deadline()), Err("client-record-binding"));
}
/// ´test:unit:protected-administrative-client-receives-observation-only-handle´
#[test]
fn protected_administrative_client_receives_observation_only_handle() {
    let _guard = crate::launch::test_support::case_guard();
    let fixture = crate::launch::inventory::tests::fixture("normal");
    let (_readers, writers) = crate::launch::inventory::tests::pipes();
    let (_child, pin) = crate::launch::inventory::tests::start(&fixture, &writers);
    let mut f = Fixture::new();
    f.value["captured"] = serde_json::to_value(pin.invocation()).unwrap();
    f.value["invocation"] = pin.invocation().id.clone().into();
    f.generator_image = pin.invocation().image;
    f.write();
    f.unit = pin.invocation().unit.clone();
    f.write();
    let mut client = f.open().unwrap();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (mut stream, _) = f.listener.accept().unwrap();
            stream.set_nonblocking(true).unwrap();
            let bytes = super::super::super::read_request(&mut stream, deadline()).unwrap();
            let request: super::super::super::Request = serde_json::from_slice(&bytes).unwrap();
            assert!(matches!(request.operation, Operation::Pidfd));
            assert_eq!(request.schema, 1);
            let binding = crate::launch::handoff::Binding {
                schema: 1,
                case: "sample",
                nonce: &request.nonce,
                keeper_pid: std::process::id(),
                keeper_birth: f.value["keeper_birth"].as_u64().unwrap(),
                keeper_uid: nix::unistd::geteuid().as_raw(),
                invocation: pin.invocation(),
                inventory_sha256: &"d".repeat(64),
            };
            // Use the retained pin's original unit in both trusted expectations.
            crate::launch::handoff::send(&mut stream, &binding, &pin, deadline()).unwrap();
        });
        client
            .observation(&"d".repeat(64), deadline())
            .unwrap()
            .verify()
            .unwrap();
        server.join().unwrap();
    });
}
