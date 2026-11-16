use super::*;
use crate::launch::control::actions::Outcome;
fn action_setup() -> (crate::launch::tests::Fixture, Control) {
    let f = crate::launch::inventory::tests::fixture("normal");
    let (_readers, writers) = crate::launch::inventory::tests::pipes();
    let (_child, pin) = crate::launch::inventory::tests::start(&f, &writers);
    setup_with(Some(pin.invocation().clone()))
}
fn action(control: &Control, operation: serde_json::Value) -> serde_json::Value {
    let mut value = request(control);
    value["schema"] = 2.into();
    value["operation"] = operation;
    value
}
/// ´test:unit:administrative-transactions-retain-peer-and-correlate-replies´
#[test]
fn administrative_transactions_retain_peer_and_correlate_replies() {
    let _case = crate::launch::test_support::case_guard();
    let (_files, control) = action_setup();
    for (operation, outcome) in [
        (
            serde_json::json!("inventory"),
            Outcome::Inventory {
                inventory_sha256: "a".repeat(64),
            },
        ),
        (
            serde_json::json!({"release":{"inventory_sha256":"a".repeat(64)}}),
            Outcome::Released {
                inventory_sha256: "a".repeat(64),
            },
        ),
    ] {
        let value = action(&control, operation);
        let (result, bytes) =
            transaction_dispatch(&control, &encoded(&value), None, true, |deadline| {
                assert!(control.ready(1, deadline)?);
                let mut transaction = control.accept(deadline)?;
                transaction.authorize()?;
                transaction.reply_action(outcome)
            });
        assert_eq!(result, Ok(()));
        let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply["schema"], 2);
        for name in ["case", "invocation", "keeper_pid", "keeper_birth", "nonce"] {
            assert_eq!(reply[name], value[name], "{name}");
        }
        assert_eq!(
            reply["outcome"]
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap()["inventory_sha256"],
            "a".repeat(64)
        );
    }
    let value = action(&control, serde_json::json!("observed"));
    let (result, bytes) =
        transaction_dispatch(&control, &encoded(&value), None, false, |deadline| {
            let transaction = control.accept(deadline)?;
            assert!(matches!(transaction.operation(), Operation::Observed));
            Ok(())
        });
    assert_eq!(result, Ok(()));
    assert_eq!(bytes.len(), 0);
}
/// ´test:unit:administrative-transactions-refuse-signallers-and-wrong-wire´
#[test]
fn administrative_transactions_refuse_signallers_and_wrong_wire() {
    let _case = crate::launch::test_support::case_guard();
    let (_files, control) = action_setup();
    for operation in [
        serde_json::json!("inventory"),
        serde_json::json!({"release":{"inventory_sha256":"a".repeat(64)}}),
    ] {
        let value = action(&control, operation);
        let (result, bytes) =
            transaction_dispatch(&control, &encoded(&value), None, false, |deadline| {
                control.accept(deadline).map(|_| ())
            });
        assert_eq!(result, Err("handoff-peer-signalling"));
        assert_eq!(bytes.len(), 0);
        let (result, bytes) =
            transaction_dispatch(&control, &encoded(&value), None, true, |deadline| {
                control.serve_once(Phase::Captured, deadline)
            });
        assert_eq!(result, Err("control-operation"));
        assert_eq!(bytes.len(), 0);
    }
    for (operation, schema, class) in [
        (serde_json::json!("inventory"), 1, "control-transaction"),
        (serde_json::json!("status"), 2, "control-transaction"),
        (
            serde_json::json!({"release":{"inventory_sha256":"a".repeat(64),"extra":true}}),
            2,
            "control-record",
        ),
    ] {
        let mut value = action(&control, operation);
        value["schema"] = schema.into();
        let (result, bytes) =
            transaction_dispatch(&control, &encoded(&value), None, true, |deadline| {
                control.accept(deadline).map(|_| ())
            });
        assert_eq!(result, Err(class));
        assert_eq!(bytes.len(), 0);
    }
    assert_eq!(control.ready(1, Instant::now()), Err("control-deadline"));
    let value = action(&control, serde_json::json!("inventory"));
    let (result, _) = transaction_dispatch(&control, &encoded(&value), None, true, |deadline| {
        let mut transaction = control.accept(deadline)?;
        transaction.deadline = Instant::now();
        transaction.authorize()
    });
    assert_eq!(result, Err("control-deadline"));
}
