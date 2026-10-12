//! Start the production service in a built subprocess with its socket namespace step substituted and its startup run beneath the fixture's activated private home.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

thread_local! {
    static SOCKET_FIXTURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn socket_fixture_enabled() -> bool {
    SOCKET_FIXTURE.with(std::cell::Cell::get)
}

struct ServiceChild(Child);

impl Drop for ServiceChild {
    fn drop(&mut self) {
        let group = nix::unistd::Pid::from_raw(self.0.id().cast_signed());
        let _killed = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
        let _reaped = self.0.wait();
    }
}

fn private_file(path: &Path, body: impl AsRef<[u8]>) {
    fs::write(path, body).expect("fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private file");
}

fn activate_home(home: &Path) -> crate::home::PrivateHomeGuard {
    let runs = home.join("runs");
    crate::home::activate_private_launch(
        home,
        &fs::File::open(home).expect("fixture home descriptor"),
        &runs,
        &fs::File::open(&runs).expect("fixture runs descriptor"),
        None,
        nix::unistd::Uid::effective().as_raw(),
    )
    .expect("pinned fixture home")
}

fn install_fixture(home: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let config = home.join(".config/loops/alpha");
    let runs = home.join("runs");
    let sockets = home.join("sockets");
    for directory in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
        home.join(".var"),
        home.join(".var/loops"),
        home.join(".var/loops/alpha"),
        home.join(".var/loops/alpha/policy"),
        config.clone(),
        runs.clone(),
        sockets.clone(),
        sockets.join("door"),
    ] {
        fs::create_dir(&directory).expect("fixture directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("private directory");
    }
    fs::set_permissions(sockets.join("door"), fs::Permissions::from_mode(0o750))
        .expect("socket directory mode");
    fs::set_permissions(
        home.join(".var/loops/alpha/policy"),
        fs::Permissions::from_mode(0o2750),
    )
    .expect("policy directory mode");
    let service = config.join("door-service");
    fs::copy(
        std::env::current_exe().expect("built test executable"),
        &service,
    )
    .expect("installed executable");
    // Debug information can exceed the production service's 64 MiB pin limit.
    // Strip only this disposable copy; validate its resulting bytes normally.
    let stripped = Command::new("/usr/bin/strip")
        .arg("--strip-all")
        .arg(&service)
        .output()
        .expect("strip fixture debug data");
    assert!(
        stripped.status.success(),
        "{}",
        String::from_utf8_lossy(&stripped.stderr)
    );
    fs::set_permissions(&service, fs::Permissions::from_mode(0o700)).expect("service mode");
    let entry = config.join("entry");
    let uid = nix::unistd::Gid::effective().as_raw();
    let row = json!({"name":"alpha","uid":uid,"runs_root":runs});
    crate::fixture_exec::write_executable(
        &entry,
        crate::registry_fixture::script(&format!(
            "printf '%s\\n' \"$@\" > \"$0.argv\"\nprintf '%s\\n' '{row}'"
        ))
        .as_bytes(),
    )
    .expect("strict entry");
    private_file(
        &home.join(".config/loops/registry.toml"),
        format!(
            "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = {uid}, launch = \"src\", runs_root = {} }}]\n",
            json!(runs)
        ),
    );
    private_file(
        &home.join(".config/loops/allocations.toml"),
        "[alpha]\nuids = { base = 3000, count = 2 }\n",
    );
    private_file(
        &config.join("workers.toml"),
        format!(
            "entry_bin = {}\nruns_root = {}\nsocket_dir = {}\ndriver_argv = [\"/usr/bin/true\"]\n",
            json!(entry),
            json!(runs),
            json!(sockets)
        ),
    );
    let agent = json!({"source":config.join("door.toml"),"rubric_root":home,"rubric_path":home.join("permissions/door.md"),"executable":"/usr/bin/true","model":"fixture","effort":"medium","cap_ms":30000,"entry":entry,"loop_home":home});
    private_file(&config.join("door-install-generation.json"), serde_json::to_vec(&json!({
        "schema":2,"phase":"complete","loop":"alpha","template_dir":home.join("template"),
        "socket_dir":sockets,"stub_sha256":"0".repeat(64),"service_sha256":crate::build::sha256(&service).expect("service digest"),
        "unit_dir":config.join("units"),"registered":["ssh"],"host_door_gid":nix::unistd::Gid::effective().as_raw(),"agent":agent
    })).expect("generation"));
    (service, entry, sockets.join("door/capability.sock"))
}

/// A wrong registry query must stop startup before the service accepts requests.
/// # Panics
/// Panics only if setup fails or the production startup cannot answer a framed request.
/// ´test:unit:service-startup-uses-show-only-registry-entry´
#[test]
fn service_startup_uses_show_only_registry_entry() {
    if std::env::var_os("SUPERLOOP_DOOR_STARTUP_FIXTURE").is_some() {
        let _home = activate_home(&crate::caller_home().expect("fixture home"));
        SOCKET_FIXTURE.with(|enabled| enabled.set(true));
        super::run_service("alpha").expect("production service startup");
        return;
    }
    let root = tempfile::tempdir().expect("lane TMPDIR fixture");
    let home = root.path().join("home");
    let (service, entry, socket) = install_fixture(&home);
    fs::remove_dir(home.join(".var/loops/alpha/policy")).expect("absent policy tier");
    let _home = activate_home(&home);
    let error_log = home.join("service.stderr");
    let mut child = ServiceChild(
        Command::new(&service)
            .args([
                "--exact",
                "door::startup_tests::service_startup_uses_show_only_registry_entry",
                "--nocapture",
            ])
            .env("HOME", &home)
            .env("TMPDIR", std::env::temp_dir())
            .env_remove("ENTER_LOOP_REGISTRY")
            .env("SUPERLOOP_DOOR_STARTUP_FIXTURE", "1")
            .process_group(0)
            .stdout(Stdio::null())
            .stderr(fs::File::create(&error_log).expect("service diagnostics"))
            .spawn()
            .expect("built service fixture"),
    );
    let slot = crate::SocketSlot::pinned(&socket, nix::unistd::Uid::effective().as_raw())
        .expect("pinned socket location");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        if let Ok(stream) = UnixStream::connect(slot.address()) {
            break stream;
        }
        assert!(
            child.0.try_wait().expect("service status").is_none() && Instant::now() < deadline,
            "service did not listen: {}",
            fs::read_to_string(&error_log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded service reply");
    // A reply proves the real accept loop ran after socket finalization; existence
    // or a successful connect alone would also observe an unfinished startup.
    super::frame_write(&mut stream, &json!({"schema":2,"type":"request"})).expect("request");
    let reply = super::frame_read(&mut stream).expect("listening service reply");
    assert_eq!(reply["reason"], "door-request-refusal", "{reply}");
    assert_eq!(
        fs::read_to_string(entry.with_extension("argv")).expect("entry arguments"),
        "show\nalpha\n"
    );
    assert!(child.0.try_wait().expect("live service").is_none());
    let diagnostics = fs::read_to_string(&error_log).expect("publication diagnostics");
    assert!(
        diagnostics.contains("direct-policy-publication"),
        "{diagnostics}"
    );
    let pid = child.0.id();
    drop(child);
    assert!(
        !Path::new("/proc").join(pid.to_string()).exists(),
        "service was reaped"
    );
}
