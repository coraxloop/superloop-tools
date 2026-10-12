use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2, renameat};
use nix::sys::stat::{Mode, fstat};
use nix::unistd::Uid;
use nix::unistd::{UnlinkatFlags, unlinkat};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static NEXT_OBSERVATION_FILE: AtomicUsize = AtomicUsize::new(0);

fn record(args: std::fmt::Arguments<'_>) {
    let _written = writeln!(io::stderr().lock(), "{args}");
}

use superloop_lane::vendor_net::public_address;

fn resolve(host: &str) -> io::Result<SocketAddr> {
    let addresses = (host, 443).to_socket_addrs()?.collect::<Vec<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !public_address(address.ip()))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DNS answer is empty or has a private or reserved address",
        ));
    }
    Ok(addresses[0])
}

fn request_host(stream: &mut UnixStream) -> io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut bytes = Vec::with_capacity(256);
    loop {
        let mut byte = [0_u8];
        if stream.read(&mut byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "CONNECT header ended early",
            ));
        }
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
        if bytes.len() >= 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT header exceeds 8192 bytes",
            ));
        }
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let line = text.split("\r\n").next().unwrap_or_default();
    let words = line.split(' ').collect::<Vec<_>>();
    if words.len() != 3 || words[0] != "CONNECT" || words[2] != "HTTP/1.1" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "only HTTP/1.1 CONNECT is allowed",
        ));
    }
    let host = words[1].strip_suffix(":443").ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "only port 443 is allowed")
    })?;
    if !superloop_lane::vendor_net::exact_dns_host(host) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "CONNECT target is not an exact DNS hostname",
        ));
    }
    Ok(host.to_owned())
}

struct Observation {
    path: PathBuf,
    runs: OwnedFd,
    run: String,
    hosts: BTreeMap<String, bool>,
}

impl Observation {
    fn publish(&self) -> io::Result<()> {
        let mut bytes = format!("mode=observing run={} enforcing=false\n", self.run).into_bytes();
        for (host, connected) in &self.hosts {
            writeln!(bytes, "{host}:443 connected={}", u8::from(*connected))?;
        }
        if bytes.len() > 32_768 || self.hosts.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "observation limit reached",
            ));
        }
        let next = self.path.with_extension(format!(
            "next-{}-{}",
            std::process::id(),
            NEXT_OBSERVATION_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let name = self
            .path
            .file_name()
            .ok_or_else(|| io::Error::other("observation name is absent"))?;
        let next_name = next
            .file_name()
            .ok_or_else(|| io::Error::other("temporary observation name is absent"))?;
        let result = (|| {
            let mut file = File::from(openat2(
                &self.runs,
                next_name,
                OpenHow::new()
                    .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
                    .mode(Mode::S_IRUSR | Mode::S_IWUSR)
                    .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
            )?);
            file.write_all(&bytes)?;
            file.sync_all()?;
            renameat(&self.runs, next_name, &self.runs, name)?;
            File::from(self.runs.as_fd().try_clone_to_owned()?).sync_all()
        })();
        if result.is_err() {
            let _ignored = unlinkat(&self.runs, next_name, UnlinkatFlags::NoRemoveDir);
        }
        result
    }

    fn note(&mut self, host: &str, connected: bool) -> io::Result<()> {
        let prior = self.hosts.get(host).copied();
        if prior.is_some_and(|value| value || !connected) {
            return Ok(());
        }
        self.hosts.insert(host.to_owned(), connected);
        if let Err(error) = self.publish() {
            match prior {
                Some(value) => {
                    self.hosts.insert(host.to_owned(), value);
                }
                None => {
                    self.hosts.remove(host);
                }
            }
            return Err(error);
        }
        Ok(())
    }
}

fn handle(
    mut client: UnixStream,
    hosts: &[String],
    observation: Option<&Arc<Mutex<Observation>>>,
) -> io::Result<()> {
    let started = Instant::now();
    let host = match request_host(&mut client) {
        Ok(host) => host,
        Err(error) => {
            let _sent = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            record(format_args!(
                "proxy-refuse reason={error} wall_seconds={}",
                started.elapsed().as_secs_f64()
            ));
            return Err(error);
        }
    };
    if let Some(state) = observation {
        state
            .lock()
            .map_err(|_| io::Error::other("observation lock poisoned"))?
            .note(&host, false)?;
        record(format_args!(
            "proxy-observe attempted_host={host} port=443 connected=false enforcing=false"
        ));
    } else if !superloop_lane::vendor_net::admitted_host(hosts, &host) {
        client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")?;
        record(format_args!(
            "proxy-refuse host={host} reason=not-allowed wall_seconds={}",
            started.elapsed().as_secs_f64()
        ));
        return Ok(());
    }
    let address = match resolve(&host) {
        Ok(address) => address,
        Err(error) => {
            client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")?;
            record(format_args!(
                "proxy-refuse host={host} reason={error} wall_seconds={}",
                started.elapsed().as_secs_f64()
            ));
            return Err(error);
        }
    };
    let mut upstream = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
    if let Some(state) = observation {
        state
            .lock()
            .map_err(|_| io::Error::other("observation lock poisoned"))?
            .note(&host, true)?;
        record(format_args!(
            "proxy-observe attempted_host={host} port=443 connected=true enforcing=false"
        ));
    }
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    client.set_read_timeout(None)?;
    let mut outbound = client.try_clone()?;
    let mut inbound = upstream.try_clone()?;
    let sender = std::thread::spawn(move || {
        let count = io::copy(&mut outbound, &mut upstream);
        let _shutdown = upstream.shutdown(Shutdown::Write);
        count
    });
    let received = io::copy(&mut inbound, &mut client)?;
    let _shutdown = client.shutdown(Shutdown::Write);
    let sent = sender
        .join()
        .map_err(|_| io::Error::other("proxy sender panicked"))??;
    if observation.is_none() {
        record(format_args!(
            "proxy-pass host={host} address={address} sent_bytes={sent} received_bytes={received} wall_seconds={}",
            started.elapsed().as_secs_f64()
        ));
    }
    Ok(())
}

type ProxyParameters = (
    PathBuf,
    u32,
    Vec<String>,
    Option<(String, PathBuf, RawFd)>,
    Option<RawFd>,
    Option<PathBuf>,
);

fn observation_root(fd: RawFd, owner: u32) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "verified runs-root descriptor is invalid",
        ));
    }
    #[allow(unsafe_code)]
    // SAFETY: the descriptor is inherited from the public launch and remains open during this call.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let stat = fstat(borrowed)?;
    if stat.st_mode & libc::S_IFMT == libc::S_IFDIR
        && stat.st_uid == owner
        && stat.st_mode & 0o022 == 0
    {
        borrowed.try_clone_to_owned()
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "verified runs-root descriptor uid {} mode {:04o} is not an owner-controlled directory for uid {owner}",
                stat.st_uid,
                stat.st_mode & 0o7777
            ),
        ))
    }
}

fn observation_state(
    observation: Option<&(String, PathBuf, RawFd)>,
    owner: u32,
) -> io::Result<Option<Arc<Mutex<Observation>>>> {
    observation
        .map(|(run, path, fd)| {
            let runs = observation_root(*fd, owner)?;
            Ok(Arc::new(Mutex::new(Observation {
                path: path.clone(),
                runs,
                run: run.clone(),
                hosts: BTreeMap::new(),
            })))
        })
        .transpose()
}

fn parameters() -> Result<ProxyParameters, String> {
    parameters_from(&std::env::args().skip(1).collect::<Vec<_>>())
}

fn parameters_from(args: &[String]) -> Result<ProxyParameters, String> {
    let mut socket = None;
    let mut group = None;
    let mut hosts = Vec::new();
    let mut observe = None;
    let mut observed_file = None;
    let mut verified_runs_fd = None;
    let mut verified_socket_fd = None;
    let mut owner_home = None;
    let mut index = 0;
    while index < args.len() {
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("{:?} needs a value", args[index]))?;
        match args[index].as_str() {
            "--socket" if socket.is_none() => socket = Some(PathBuf::from(value)),
            "--group" if group.is_none() => {
                group = Some(
                    value
                        .parse::<u32>()
                        .map_err(|error| format!("--group: {error}"))?,
                );
            }
            "--host" if !hosts.contains(value) => hosts.push(value.clone()),
            "--observe" if observe.is_none() => observe = Some(value.clone()),
            "--observed-file" if observed_file.is_none() => {
                observed_file = Some(PathBuf::from(value));
            }
            "--verified-runs-root-fd" if verified_runs_fd.is_none() => {
                verified_runs_fd = Some(
                    value
                        .parse::<RawFd>()
                        .map_err(|error| format!("--verified-runs-root-fd: {error}"))?,
                );
            }
            "--verified-socket-dir-fd" if verified_socket_fd.is_none() => {
                verified_socket_fd = Some(
                    value
                        .parse::<RawFd>()
                        .map_err(|error| format!("--verified-socket-dir-fd: {error}"))?,
                );
            }
            "--owner-home" if owner_home.is_none() => owner_home = Some(PathBuf::from(value)),
            option => return Err(format!("unexpected or repeated option {option:?}")),
        }
        index += 2;
    }
    let socket = socket.ok_or("--socket is absent")?;
    if !socket.is_absolute() {
        return Err("absolute --socket is required".into());
    }
    let observation = match (observe, observed_file, verified_runs_fd) {
        (Some(run), Some(path), Some(fd))
            if superloop_lane::valid_run_name(&run)
                && path.is_absolute()
                && fd >= 0
                && path.file_name().is_some_and(|name| {
                    name == std::ffi::OsStr::new(&format!(".observed-{run}.txt"))
                }) =>
        {
            Some((run, path, fd))
        }
        (None, None, None) if !hosts.is_empty() => None,
        _ => {
            return Err(
                "observing needs one run, its absolute evidence file and verified runs-root descriptor; enforcing needs hosts".into(),
            );
        }
    };
    if observation.is_some() && !hosts.is_empty() {
        return Err("observing cannot use an enforced host list".into());
    }
    Ok((
        socket,
        group.ok_or("--group is absent")?,
        hosts,
        observation,
        verified_socket_fd,
        owner_home,
    ))
}

fn socket_directory(
    socket: &Path,
    owner_home: &Path,
    fd: RawFd,
    owner: u32,
) -> io::Result<OwnedFd> {
    let parent = socket.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket-dir-handoff: socket parent is absent",
        )
    })?;
    superloop_lane::home::bind_socket_directory(parent, owner_home, fd, owner)
        .map_err(io::Error::other)
}

fn serve(
    socket: &Path,
    group: u32,
    hosts: &[String],
    observation: Option<&(String, PathBuf, RawFd)>,
    socket_fd: Option<RawFd>,
    owner_home: Option<&Path>,
) -> io::Result<()> {
    if Uid::effective().as_raw() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "rootless namespace root is required",
        ));
    }
    let socket_fd = socket_fd.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "verified socket directory descriptor is absent",
        )
    })?;
    let owner_home = owner_home.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket-dir-handoff: owner home is absent",
        )
    })?;
    let directory = socket_directory(socket, owner_home, socket_fd, 0)?;
    if let Some((_, path, fd)) = observation {
        let runs = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket-dir-handoff: runs root is absent",
            )
        })?;
        let prefix = if runs.starts_with(owner_home) {
            owner_home
        } else {
            runs
        };
        let _verified_runs = superloop_lane::home::bind_socket_directory(runs, prefix, *fd, 0)
            .map_err(io::Error::other)?;
    }
    let name = socket
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket name is absent"))?;
    let slot = superloop_lane::SocketSlot::new(directory, name)?;
    let observation_state = observation_state(observation, 0)?;
    if let Some(state) = &observation_state {
        state
            .lock()
            .map_err(|_| io::Error::other("observation lock poisoned"))?
            .publish()?;
    }
    if let Some(meta) = slot.metadata()? {
        if meta.st_mode & libc::S_IFMT != libc::S_IFSOCK || meta.st_uid != 0 || meta.st_gid != group
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} differs from the expected socket", socket.display()),
            ));
        }
        slot.remove()?;
    }
    let listener = UnixListener::bind(slot.address())?;
    slot.set_owner_mode(0, group, 0o660)?;
    record(format_args!(
        "proxy-ready socket={} owner_uid=0 group_gid={group} mode=0660 hosts={} mode={}",
        socket.display(),
        hosts.join(","),
        if observation.is_some() {
            "observing-not-enforcing"
        } else {
            "enforcing"
        }
    ));
    let active = Arc::new(AtomicUsize::new(0));
    for client in listener.incoming() {
        let client = client?;
        if active.fetch_add(1, Ordering::AcqRel) >= 64 {
            active.fetch_sub(1, Ordering::AcqRel);
            let mut client = client;
            let _sent = client.write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
            continue;
        }
        let hosts = hosts.to_vec();
        let observed = observation_state.clone();
        let active = Arc::clone(&active);
        std::thread::spawn(move || {
            let _handled = handle(client, &hosts, observed.as_ref());
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}

fn main() {
    superloop_cli_common::version_or_exit("vendor-proxy", env!("CARGO_PKG_VERSION"), None);
    let result = parameters().map_err(io::Error::other).and_then(
        |(socket, group, hosts, observation, socket_fd, owner_home)| {
            serve(
                &socket,
                group,
                &hosts,
                observation.as_ref(),
                socket_fd,
                owner_home.as_deref(),
            )
        },
    );
    if let Err(error) = result {
        record(format_args!("proxy-fail: {error}"));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::IpAddr;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixStream;

    use super::{
        Observation, handle, observation_state, parameters_from, public_address, request_host,
        socket_directory,
    };

    /// ´test:unit:proxy-socket-directory-handoff-refuses-a-different-directory´
    #[test]
    fn proxy_socket_directory_handoff_refuses_a_different_directory() {
        let fixture = tempfile::TempDir::new().expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("private root");
        let expected = fixture.path().join("vendor");
        let other = fixture.path().join("other");
        fs::create_dir(&expected).expect("expected directory");
        fs::create_dir(&other).expect("other directory");
        fs::set_permissions(&expected, fs::Permissions::from_mode(0o700))
            .expect("private expected");
        fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).expect("private other");
        let socket = expected.join("proxy.sock");
        let owner = nix::unistd::Uid::effective().as_raw();
        let wrong = fs::File::open(&other).expect("wrong descriptor");
        let error = socket_directory(&socket, fixture.path(), wrong.as_raw_fd(), owner)
            .expect_err("different directory refused before bind");
        assert!(error.to_string().contains("socket-dir-handoff"));
        assert!(error.to_string().contains("expected"));
        assert!(error.to_string().contains("received"), "{error}");
        assert!(!socket.exists());
        let matching = fs::File::open(&expected).expect("matching descriptor");
        socket_directory(&socket, fixture.path(), matching.as_raw_fd(), owner)
            .expect("matching directory accepted");
    }

    /// ´test:unit:proxy-malformed-option-is-one-refusal-line´
    #[test]
    fn proxy_malformed_option_is_one_refusal_line() {
        let error = parameters_from(&["--bad\noption".into(), "value".into()])
            .expect_err("malformed option refused");
        assert!(!error.contains('\n'));
        assert!(error.contains("\\n"));
        let missing =
            parameters_from(&["--bad\noption".into()]).expect_err("missing option value refused");
        assert!(!missing.contains('\n'));
        assert!(missing.contains("\\n"));
    }

    /// ´test:unit:proxy-rejects-private-and-reserved-addresses´
    #[test]
    fn proxy_rejects_private_and_reserved_addresses() {
        for address in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.1.1",
            "192.168.1.1",
            "198.51.100.4",
            "192.88.99.2",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "3fff::1",
            "2002::1",
        ] {
            assert!(
                !public_address(address.parse::<IpAddr>().expect("address")),
                "{address}"
            );
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(
                public_address(address.parse::<IpAddr>().expect("address")),
                "{address}"
            );
        }
    }

    /// ´test:unit:proxy-observation-is-distinct-bounded-and-marks-connected-attempts´
    #[test]
    fn proxy_observation_is_distinct_bounded_and_marks_connected_attempts() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let path = fixture.path().join("observed-hosts.txt");
        let mut state = Observation {
            path: path.clone(),
            runs: fs::File::open(fixture.path()).expect("runs root").into(),
            run: "R".into(),
            hosts: BTreeMap::default(),
        };
        state.publish().expect("marker");
        state.note("api.example.com", false).expect("attempt");
        state.note("api.example.com", false).expect("same attempt");
        state.note("api.example.com", true).expect("connected");
        let text = fs::read_to_string(&path).expect("observation");
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("api.example.com:443 connected=1"));
        for number in 0..127 {
            state
                .note(&format!("host{number}.example.com"), false)
                .expect("within bound");
        }
        assert!(state.note("overflow.example.com", false).is_err());
        assert!(fs::metadata(&path).expect("bounded file").len() < 32_768);
        assert_eq!(
            fs::read_to_string(&path)
                .expect("retained file")
                .lines()
                .count(),
            129
        );
    }

    /// ´test:unit:proxy-observation-writes-beneath-inherited-root-without-absolute-walk´
    #[test]
    fn proxy_observation_writes_beneath_inherited_root_without_absolute_walk() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("runs root");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected runs root");
        let outside = std::path::PathBuf::from("/overflow-owned/.observed-R.txt");
        let runs = fs::File::open(fixture.path()).expect("runs descriptor");
        let state = observation_state(
            Some(&(String::from("R"), outside, runs.as_raw_fd())),
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("serve preparation")
        .expect("observation state");
        state
            .lock()
            .expect("observation lock")
            .publish()
            .expect("descriptor-pinned observation");
        assert_eq!(
            fs::read_to_string(fixture.path().join(".observed-R.txt")).expect("beneath root"),
            "mode=observing run=R enforcing=false\n"
        );
        let without_fd = parameters_from(&[
            "--socket".into(),
            "/tmp/proxy.sock".into(),
            "--group".into(),
            "2001".into(),
            "--observe".into(),
            "R".into(),
            "--observed-file".into(),
            "/overflow-owned/.observed-R.txt".into(),
        ])
        .expect_err("absolute walk form refused");
        assert!(without_fd.contains("verified runs-root descriptor"));
    }

    /// ´test:unit:proxy-accepts-only-exact-connect-targets´
    #[test]
    fn proxy_accepts_only_exact_connect_targets() {
        for (request, expected) in [
            (
                "CONNECT api.example.com:443 HTTP/1.1\r\n\r\n",
                Some("api.example.com"),
            ),
            ("CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n", None),
            ("CONNECT api.example.com:80 HTTP/1.1\r\n\r\n", None),
            ("GET api.example.com:443 HTTP/1.1\r\n\r\n", None),
        ] {
            let (mut writer, mut reader) = UnixStream::pair().expect("socket pair");
            writer.write_all(request.as_bytes()).expect("write request");
            let actual = request_host(&mut reader).ok();
            assert_eq!(actual.as_deref(), expected);
        }
    }

    /// ´test:unit:proxy-refuses-unlisted-and-literal-targets-before-resolution´
    #[test]
    fn proxy_refuses_unlisted_and_literal_targets_before_resolution() {
        let hosts = vec!["api.example.com".to_owned()];
        for (name, target) in [
            ("other", "other.example.com"),
            ("new", "new.example.com"),
            ("literal", "1.1.1.1"),
        ] {
            let (mut caller, peer) = UnixStream::pair().expect("fixture socket");
            caller
                .write_all(format!("CONNECT {target}:443 HTTP/1.1\r\n\r\n").as_bytes())
                .expect("request");
            let _refused = handle(peer, &hosts, None);
            let mut response = String::new();
            caller
                .read_to_string(&mut response)
                .expect("proxy response");
            assert!(
                response.starts_with("HTTP/1.1 403 Forbidden"),
                "{name}: {response}"
            );
        }
        assert!(!superloop_lane::vendor_net::admitted_host(
            &hosts,
            "new.example.com"
        ));
        let changed = vec!["api.example.com".to_owned(), "new.example.com".to_owned()];
        assert!(superloop_lane::vendor_net::admitted_host(
            &changed,
            "new.example.com"
        ));
    }
}
