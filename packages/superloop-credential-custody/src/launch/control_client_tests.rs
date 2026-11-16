use super::*;
use std::{
    fs,
    net::Shutdown,
    os::unix::{
        fs::{PermissionsExt as _, symlink},
        net::UnixListener,
    },
    time::Duration,
};
struct Fixture {
    dir: tempfile::TempDir,
    listener: UnixListener,
    value: serde_json::Value,
    image: ObjectIdentity,
    generator_image: ObjectIdentity,
    unit: String,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let directory = File::open(dir.path()).unwrap();
        let socket =
            ObjectIdentity::of(&file(&directory, "control.sock", OFlag::O_PATH).unwrap()).unwrap();
        let image = ObjectIdentity::of(&File::open("/proc/self/exe").unwrap()).unwrap();
        let (birth, _) =
            crate::launch::process_pin::stat(&File::open("/proc/self").unwrap()).unwrap();
        let value = serde_json::json!({"schema":2,"case":"sample","invocation":"a".repeat(32),
            "keeper_pid":std::process::id(),"keeper_birth":birth,"image":image,"socket":socket,
            "policy_sha256":"b".repeat(64),"case_sha256":"c".repeat(64),
            "captured":{"id":"a".repeat(32),"unit":"sample.service","pid":123,"birth":456,"uid":1234,"image":image}});
        let f = Self {
            dir,
            listener,
            value,
            image,
            generator_image: image,
            unit: "sample.service".into(),
        };
        f.write();
        f
    }
    fn write(&self) {
        let path = self.dir.path().join("control-manifest.json");
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        fs::write(&path, serde_json::to_vec(&self.value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    fn open(&self) -> Result<Opened> {
        Opened::open(
            self.dir.path(),
            &Expected {
                case: "sample",
                policy: &"b".repeat(64),
                public_case: &"c".repeat(64),
                image: self.image,
                owner: nix::unistd::geteuid().as_raw(),
                unit: &self.unit,
                fixture: self.generator_image,
                sealed_limit: 4096,
            },
            deadline(),
        )
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(600)
}

/// ´test:unit:protected-client-opens-and-requests-completion´
#[test]
fn protected_client_opens_and_requests_completion() {
    let _case = crate::launch::test_support::case_guard();
    for complete in [false, true] {
        let f = Fixture::new();
        let mut client = f.open().unwrap();
        std::thread::scope(|scope| {
            let worker=scope.spawn(|| {
                let (mut stream,_)=f.listener.accept().unwrap();
                stream.set_nonblocking(true).unwrap();
                let bytes=super::super::read_request(&mut stream,deadline()).unwrap();
                let request:super::super::Request=serde_json::from_slice(&bytes).unwrap();
                assert!(matches!(request.operation,super::super::Operation::Completion));
                let view=if complete {serde_json::json!({"phase":"complete",
                    "generator":{"invocation":f.value["captured"],"started":100,"exited":200,"code":1,"status":0,"result":"success","successful":true,"reply_sha256":"d".repeat(64),"configuration_sha256":"e".repeat(64)},
                    "sealers":{"sealed_bytes":[4,4],"eof":[true,true],"exits":[{"Code":0},{"Code":0}]}})}
                    else {serde_json::json!({"phase":"captured","generator":null,"sealers":null})};
                let mut reply=serde_json::to_vec(&serde_json::json!({"schema":1,"case":"sample","invocation":"a".repeat(32),"keeper_pid":std::process::id(),"keeper_birth":f.value["keeper_birth"],"nonce":request.nonce,"view":view})).unwrap();
                reply.push(b'\n');
                super::super::write_record(&mut stream,&reply,deadline()).unwrap();
                stream.shutdown(Shutdown::Write).unwrap();
            });
            assert_eq!(
                client.completion(deadline()),
                Ok(if complete {
                    completion_client::Observation::Complete
                } else {
                    completion_client::Observation::Pending
                })
            );
            worker.join().unwrap();
        });
    }
}

/// ´test:unit:protected-client-refuses-manifest-and-peer-drift´
#[test]
fn protected_client_refuses_manifest_and_peer_drift() {
    let _case = crate::launch::test_support::case_guard();
    for (key, value, class) in [
        ("schema", serde_json::json!(1), "client-binding"),
        ("case", serde_json::json!("foreign"), "client-binding"),
        (
            "policy_sha256",
            serde_json::json!("d".repeat(64)),
            "client-binding",
        ),
        (
            "case_sha256",
            serde_json::json!("d".repeat(64)),
            "client-binding",
        ),
        ("keeper_pid", serde_json::json!(123), "client-peer"),
        ("keeper_birth", serde_json::json!(1), "client-birth"),
        ("unexpected", serde_json::json!(true), "client-manifest"),
    ] {
        let mut f = Fixture::new();
        f.value[key] = value;
        f.write();
        assert_eq!(f.open().err(), Some(class), "{key}");
    }
    for id in ["0".repeat(32), "A".repeat(32), "short".into()] {
        let mut f = Fixture::new();
        f.value["invocation"] = id.clone().into();
        f.value["captured"]["id"] = id.into();
        f.write();
        assert_eq!(f.open().err(), Some("client-binding"));
    }
    for key in ["pid", "birth", "uid"] {
        let mut f = Fixture::new();
        f.value["captured"][key] = 0.into();
        f.write();
        assert_eq!(f.open().err(), Some("client-binding"));
    }
    let mut f = Fixture::new();
    f.value["captured"]["unit"] = "foreign.service".into();
    f.write();
    assert_eq!(f.open().err(), Some("client-binding"));
    let mut f = Fixture::new();
    f.value["image"]["inode"] = 0.into();
    f.write();
    assert_eq!(f.open().err(), Some("client-binding"));
}

/// ´test:unit:protected-client-refuses-file-socket-and-ancestor-custody-loss´
#[test]
fn protected_client_refuses_file_socket_and_ancestor_custody_loss() {
    let _case = crate::launch::test_support::case_guard();
    for fault in [
        "mode",
        "link",
        "symlink",
        "socket-mode",
        "socket-object",
        "directory",
    ] {
        let f = Fixture::new();
        let path = f.dir.path().join("control-manifest.json");
        match fault {
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap(),
            "link" => fs::hard_link(&path, f.dir.path().join("alias")).unwrap(),
            "symlink" => {
                fs::rename(&path, f.dir.path().join("old")).unwrap();
                symlink("old", &path).unwrap();
            }
            "socket-mode" => fs::set_permissions(
                f.dir.path().join("control.sock"),
                fs::Permissions::from_mode(0o666),
            )
            .unwrap(),
            "socket-object" => {
                fs::remove_file(f.dir.path().join("control.sock")).unwrap();
                fs::write(f.dir.path().join("control.sock"), b"wrong").unwrap();
            }
            _ => fs::set_permissions(f.dir.path(), fs::Permissions::from_mode(0o777)).unwrap(),
        }
        let class = f.open().err();
        assert_eq!(
            class,
            Some(match fault {
                "mode" | "link" => "file-custody",
                "symlink" => "client-object",
                "socket-mode" | "socket-object" => "client-socket-binding",
                _ => "sealed-directory-custody",
            }),
            "{fault}"
        );
    }
}

/// ´test:unit:protected-client-rechecks-held-objects-after-connection´
#[test]
fn protected_client_rechecks_held_objects_after_connection() {
    let _case = crate::launch::test_support::case_guard();
    for fault in ["record", "bytes", "socket", "directory", "representation"] {
        let mut f = Fixture::new();
        let client = f.open().unwrap();
        if fault == "directory" {
            let moved = f.dir.path().with_extension("moved");
            fs::rename(f.dir.path(), &moved).unwrap();
            fs::create_dir(f.dir.path()).unwrap();
            fs::set_permissions(f.dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(client.verify(), Err("client-directory-binding"));
            fs::remove_dir_all(&moved).unwrap();
            continue;
        }
        if fault == "record" {
            f.write();
        } else if fault == "bytes" || fault == "representation" {
            let path = f.dir.path().join("control-manifest.json");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            if fault == "bytes" {
                f.value["keeper_birth"] = 1.into();
            }
            let mut bytes = serde_json::to_vec(&f.value).unwrap();
            if fault == "representation" {
                bytes.push(b' ');
            }
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        } else {
            fs::set_permissions(
                f.dir.path().join("control.sock"),
                fs::Permissions::from_mode(0o666),
            )
            .unwrap();
        }
        assert_eq!(
            client.verify(),
            Err(if fault == "socket" {
                "client-socket-binding"
            } else {
                "client-record-binding"
            })
        );
    }
}

/// ´test:unit:protected-client-bounds-records-before-connect´
#[test]
fn protected_client_bounds_records_before_connect() {
    let _case = crate::launch::test_support::case_guard();
    for fault in ["missing", "oversize", "duplicate", "incomplete", "expired"] {
        let f = Fixture::new();
        let path = f.dir.path().join("control-manifest.json");
        let result = if fault == "expired" {
            Opened::open(
                f.dir.path(),
                &Expected {
                    case: "sample",
                    policy: &"b".repeat(64),
                    public_case: &"c".repeat(64),
                    image: f.image,
                    owner: nix::unistd::geteuid().as_raw(),
                    unit: "sample.service",
                    fixture: f.image,
                    sealed_limit: 4096,
                },
                Instant::now(),
            )
            .err()
        } else {
            fs::remove_file(&path).unwrap();
            if fault != "missing" {
                let bytes = match fault {
                    "oversize" => vec![b' '; 16 * 1024 + 1],
                    "duplicate" => serde_json::to_vec(&f.value)
                        .unwrap()
                        .into_iter()
                        .skip(1)
                        .collect(),
                    _ => b"{}".to_vec(),
                };
                let bytes = if fault == "duplicate" {
                    [b"{\"schema\":2,".as_slice(), &bytes].concat()
                } else {
                    bytes
                };
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            }
            f.open().err()
        };
        assert_eq!(
            result,
            Some(match fault {
                "expired" => "control-deadline",
                "missing" => "client-object",
                "oversize" => "file-custody",
                _ => "client-manifest",
            }),
            "{fault}"
        );
    }
}

#[path = "control_client_action_tests.rs"]
mod action_tests;
