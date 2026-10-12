use std::io::{self, Write as _};
fn main() {
    superloop_cli_common::version_or_exit("door-service", env!("CARGO_PKG_VERSION"), None);
    let mut args = std::env::args().skip(1);
    let Some(loop_name) = args.next() else {
        let _written = writeln!(io::stderr().lock(), "door-service-usage: LOOP");
        std::process::exit(2);
    };
    if loop_name == "_set-socket-group" {
        let words = args.collect::<Vec<_>>();
        match superloop_lane::door::run_socket_group_private(&words) {
            Ok(uid_map) => {
                let _written = writeln!(
                    io::stdout().lock(),
                    "{}",
                    serde_json::json!({"schema":1,"status":"door-socket-ready","uid_map":uid_map})
                );
            }
            Err(error) => {
                let _written = writeln!(io::stderr().lock(), "{}", error.line());
                std::process::exit(i32::from(error.status));
            }
        }
        return;
    }
    if args.next().is_some() {
        let _written = writeln!(io::stderr().lock(), "door-service-usage: LOOP");
        std::process::exit(2);
    }
    if let Err(error) = superloop_lane::door::run_service(&loop_name) {
        let _written = writeln!(io::stderr().lock(), "{}", error.line());
        std::process::exit(i32::from(error.status));
    }
}
