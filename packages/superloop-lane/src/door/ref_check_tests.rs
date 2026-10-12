// Transport fixtures for the exact outcome of the first receive packet.

fn receive_packet(reference: &str) -> Vec<u8> {
    let old = "0".repeat(40);
    let new = "1".repeat(40);
    let command = format!("{old} {new} {reference}\0 report-status\n");
    let mut input = format!("{:04x}", command.len() + 4).into_bytes();
    input.extend_from_slice(command.as_bytes());
    input.extend_from_slice(b"0000");
    input
}

fn receive_args() -> [OsString; 2] {
    [
        OsString::from("fixture"),
        OsString::from("git-receive-pack '~/mirrors/R.git'"),
    ]
}

/// ´test:unit:door-receive-matched-packet-records-admitted-and-stdin-bytes´
#[test]
fn door_receive_matched_packet_records_admitted_and_stdin_bytes() {
    let (temp, socket, server) = fixture(Scope::Work);
    let reply = stub_call(&socket, &receive_args(), &receive_packet("refs/heads/lane/R"))
        .expect("matched receive");
    assert_eq!(reply["reason"], "door-complete");
    assert_eq!(reply["ref_check"], "admitted");
    server.join().expect("server join").expect("server reply");
    let records = temp.store().list_run("R").expect("request records");
    assert_eq!(records[0].value()["effect"]["ref_check"], "admitted");
    assert_eq!(
        records[0].value()["effect"]["stdin_bytes"],
        receive_packet("refs/heads/lane/R").len()
    );
}

/// ´test:unit:door-receive-changed-packet-records-refused-and-stdin-bytes´
#[test]
fn door_receive_changed_packet_records_refused_and_stdin_bytes() {
    let (temp, socket, server) = fixture(Scope::Work);
    let reply = stub_call(&socket, &receive_args(), &receive_packet("refs/heads/lane/S"))
        .expect("changed receive");
    assert_eq!(reply["reason"], "door-changed-ref-refusal");
    assert_eq!(reply["ref_check"], "refused");
    server.join().expect("server join").expect("server reply");
    let records = temp.store().list_run("R").expect("request records");
    assert_eq!(records[0].value()["effect"]["ref_check"], "refused");
    assert_eq!(
        records[0].value()["effect"]["stdin_bytes"],
        receive_packet("refs/heads/lane/S").len()
    );
}

/// ´test:unit:door-receive-flush-without-ref-records-no-ref´
#[test]
fn door_receive_flush_without_ref_records_no_ref() {
    let (temp, socket, server) = fixture(Scope::Work);
    let reply = stub_call(&socket, &receive_args(), b"0000").expect("no-op receive");
    assert_eq!(reply["reason"], "door-complete");
    assert_eq!(reply["ref_check"], "no-ref");
    server.join().expect("server join").expect("server reply");
    let records = temp.store().list_run("R").expect("request records");
    assert_eq!(records[0].value()["effect"]["ref_check"], "no-ref");
}

/// ´test:unit:door-receive-deadline-before-packet-records-not-reached´
#[test]
fn door_receive_deadline_before_packet_records_not_reached() {
    use std::io::Write as _;

    // This exercises a real socket timeout. Allow five seconds for the request
    // to reach packet reception: the old 100 ms budget also covered durable
    // mediation writes and could expire before compute on a loaded node.
    const RECEIVE_DEADLINE_MS: u64 = 5000;
    let (temp, socket, server) = fixture(Scope::Work);
    let started = Instant::now();
    let mut client = UnixStream::connect(&socket).expect("receive client");
    let deadline = Instant::now() + Duration::from_secs(120);
    frame_write_until(
        &mut client,
        &json!({"schema":2,"argv":[b"fixture".to_vec(),
            b"git-receive-pack '~/mirrors/R.git'".to_vec()],"deadline_ms":RECEIVE_DEADLINE_MS}),
        deadline,
    )
    .expect("receive request");
    client.write_all(b"000a").expect("incomplete packet");
    let reply = frame_read_until(&mut client, deadline).expect("deadline reply");
    assert!(started.elapsed() >= Duration::from_millis(RECEIVE_DEADLINE_MS));
    assert_eq!(reply["ref_check"], "not-reached");
    assert!(matches!(
        reply["reason"].as_str(),
        Some("door-deadline-refusal" | "door-git-packet-refusal")
    ), "packet-phase refusal: {reply}");
    server.join().expect("server join").expect("server reply");
    let records = temp.store().list_run("R").expect("request records");
    assert_eq!(records[0].value()["effect"]["ref_check"], "not-reached");
}

/// ´test:unit:door-upload-records-not-applicable-ref-check´
#[test]
fn door_upload_records_not_applicable_ref_check() {
    let (temp, socket, server) = fixture(Scope::Work);
    let args = [
        OsString::from("fixture"),
        OsString::from("git-upload-pack '~/mirrors/R.git'"),
    ];
    let reply = stub_call(&socket, &args, b"").expect("upload");
    assert_eq!(reply["ref_check"], "not-applicable");
    server.join().expect("server join").expect("server reply");
    let records = temp.store().list_run("R").expect("request records");
    assert_eq!(records[0].value()["effect"]["ref_check"], "not-applicable");
}
