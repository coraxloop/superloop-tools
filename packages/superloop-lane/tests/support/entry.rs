use std::process::Output;

/// Retry only the transient fork-inherited executable writer race.
///
/// # Panics
/// Panics if ETXTBSY persists for five seconds.
pub fn retry_busy_entry(
    mut output: impl FnMut() -> std::io::Result<Output>,
) -> std::io::Result<Output> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match output() {
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "fixture-entry-busy: ETXTBSY exceeded five seconds"
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            result => return result,
        }
    }
}
