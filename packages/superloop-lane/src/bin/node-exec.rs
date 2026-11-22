//! Installed protocol-one workspace entry on the registered compute node.
use std::io::{self, Write as _};
use std::path::Path;

fn main() {
    superloop_cli_common::version_or_exit(
        "superloop-lane-node-exec",
        env!("CARGO_PKG_VERSION"),
        None,
    );
    if std::env::args_os().len() != 1 {
        let _written = writeln!(io::stderr().lock(), "node-exec-usage: no arguments");
        std::process::exit(2);
    }
    if let Err(error) = superloop_lane::workspace_node::serve(
        io::stdin(),
        io::stdout().lock(),
        Path::new("/etc/superloop/node-identity"),
        0,
    ) {
        let _written = writeln!(io::stderr().lock(), "node-exec-refusal: {error}");
        std::process::exit(1);
    }
}
